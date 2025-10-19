from flask import Flask, jsonify, current_app
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt, get_jwt_identity, decode_token
)
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timezone, timedelta

from config import Config
from models import db, Usuario, Cliente, Perfil, SesionActiva, SiigoCredencial
from flask_cors import CORS
import os
from cryptography.fernet import Fernet, InvalidToken
import base64, json, requests
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from siigo_api import auth as siigo_auth, SiigoError


FERNET_KEY = os.environ.get("APP_CRYPTO_KEY")  # genera una vez y guárdala en .env
fernet = Fernet(FERNET_KEY) if FERNET_KEY else None

PARTNER_ID_DEFAULT = "ProjectManagerApp"

def enc(b: str | None) -> bytes | None:
    if not b: return None
    if not fernet: return b.encode()
    return fernet.encrypt(b.encode())

def dec(b: bytes | None) -> str | None:
    if b is None: return None
    if not fernet: return b.decode()
    try:
        return fernet.decrypt(b).decode()
    except InvalidToken:
        return None

def cleanup_expired_sessions():
    now = datetime.now(timezone.utc)
    # borra sesiones expiradas si el token ya venció
    SesionActiva.query.filter(
        SesionActiva.expira_en.isnot(None),
        SesionActiva.expira_en < now
    ).delete(synchronize_session=False)
    db.session.commit()


def _looks_like_b64(s: str) -> bool:
    try:
        base64.b64decode(s + "==", validate=True)
        return True
    except Exception:
        return False

def _decoded_has_colon(s: str) -> bool:
    try:
        return ":" in base64.b64decode(s + "==").decode("utf-8", "ignore")
    except Exception:
        return False


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # ✅ CORS en la instancia CORRECTA
    CORS(
        app,
        resources={r"/*": {
            "origins": ["http://localhost:3000", "http://127.0.0.1:3000", "http://192.168.0.55:3000"],
            "allow_headers": ["Content-Type", "Authorization"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "supports_credentials": True,
        }}
    )

    db.init_app(app)
    jwt = JWTManager(app)  # ← guarda la instancia

    # ---- revocación en memoria (en prod usa BD o Redis) ----
    BLOCKLIST = set()

    @jwt.token_in_blocklist_loader
    def is_token_revoked(jwt_header, jwt_payload):
        return jwt_payload.get("jti") in BLOCKLIST

    @jwt.invalid_token_loader
    def invalid_token(reason):
        return jsonify({"error": f"Invalid token: {reason}"}), 422

    @jwt.unauthorized_loader
    def missing_token(reason):
        return jsonify({"error": f"Missing token: {reason}"}), 401
    
    # (opcional) tokens expirados:
    @jwt.expired_token_loader
    def expired_token(jwt_header, jwt_payload):
        return jsonify({"error": "Token expirado"}), 401

    # Ruta de prueba
    @app.route("/")
    def index():
        return {"message": "Backend Siigo Insights funcionando ✅"}

    # Login con JWT
    @app.route("/auth/login", methods=["POST"])
    def login():
        data = request.get_json()

        if not data or "email" not in data or "password" not in data:
            return jsonify({"error": "Email y password requeridos"}), 400

        email = data["email"]
        password = data["password"]

        # Buscar usuario en la BD
        user = Usuario.query.filter_by(email=email).first()
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404

        # Verificar password
        if not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Password incorrecto"}), 401

        # ========================
        # Detectar si es SuperAdmin
        # ========================
        if user.email == "superadmin@sistema.com":
            claims = {
                "idusuario": user.idusuario,
                "email": user.email,
                "perfilid": 0,       # 👑 SuperAdmin
                "idcliente": None    # 👑 No pertenece a un cliente
            }
        else:
            claims = {
                "idusuario": user.idusuario,
                "email": user.email,
                "perfilid": user.idperfil,
                "idcliente": user.idcliente
            }

        # Generar token con identity simple y claims adicionales
        is_superadmin = (user.email == "superadmin@sistema.com")

        extra_claims = {
            "idusuario": user.idusuario,
            "email": user.email,
            "perfilid": 0 if is_superadmin else user.idperfil,
            "idcliente": None if is_superadmin else user.idcliente,
        }

        # identity como string (recomendado por flask-jwt-extended)
        # (opcional) ajusta la expiración
        expires = timedelta(hours=4)
        access_token = create_access_token(
            identity=str(user.idusuario),
            additional_claims=extra_claims,
            expires_delta=expires
        )

        # Limpia sesiones expiradas
        cleanup_expired_sessions()

        # Obtén jti y exp del token
        decoded = decode_token(access_token)
        jti = decoded["jti"]
        exp_ts = decoded.get("exp")
        expira_en = datetime.fromtimestamp(exp_ts, tz=timezone.utc) if exp_ts else None

        # Enforzar límite de sesiones por cliente (superadmin no cuenta)
        idcliente = None if is_superadmin else user.idcliente
        if idcliente:
            cliente = Cliente.query.get(idcliente)
            limite = cliente.limite_sesiones or None
            if limite:
                activas = SesionActiva.query.filter_by(idcliente=idcliente).count()
                if activas >= limite:
                    return jsonify({"error": "Se alcanzó el límite de sesiones activas para este cliente."}), 429

        # Registrar sesión activa
        db.session.add(SesionActiva(
            jti=jti,
            idusuario=user.idusuario,
            idcliente=idcliente,
            expira_en=expira_en
        ))
        db.session.commit()

        return jsonify({"access_token": access_token, "usuario": user.email})


    @app.route("/auth/logout", methods=["POST"])
    @jwt_required()
    def logout():
        payload = get_jwt()
        jti = payload["jti"]

        # revoca en blocklist
        BLOCKLIST.add(jti)

        # elimina de sesiones activas (si existe)
        ses = SesionActiva.query.filter_by(jti=jti).first()
        if ses:
            db.session.delete(ses)
            db.session.commit()

        return jsonify({"message": "Sesión cerrada"}), 200



    # ==========================
    # CRUD Clientes
    # ==========================

    @app.route("/clientes", methods=["GET"])
    @jwt_required()
    def get_clientes():
        claims = get_jwt()
        if claims["perfilid"] == 0:  # SuperAdmin puede ver todos los clientes
            clientes = Cliente.query.all()
        else:
            # Un usuario normal solo puede ver su propio cliente
            clientes = Cliente.query.filter_by(idcliente=claims["idcliente"]).all()
        return jsonify([c.as_dict() for c in clientes])

    @app.route("/clientes", methods=["POST"])
    @jwt_required()
    def create_cliente():
        claims = get_jwt()
        if claims["perfilid"] != 0:
            return jsonify({"error": "No autorizado"}), 403

        data = request.get_json() or {}
        cliente = Cliente(
            nombre=data["nombre"],
            nit=data.get("nit"),
            email=data.get("email"),
            activo=bool(data.get("activo", True)),
            pais=data.get("pais"),
            ciudad=data.get("ciudad"),
            direccion=data.get("direccion"),
            telefono1=data.get("telefono1"),
            logo_url=data.get("logo_url"),
            limite_usuarios=(int(data["limite_usuarios"]) if data.get("limite_usuarios") not in (None, "",) else None),
            limite_sesiones=(int(data["limite_sesiones"]) if data.get("limite_sesiones") not in (None, "",) else None),
        )
        db.session.add(cliente)
        db.session.commit()
        return jsonify(cliente.as_dict()), 201

    @app.route("/clientes/<int:idcliente>", methods=["PUT"])
    @jwt_required()
    def update_cliente(idcliente):
        claims = get_jwt()
        cliente = Cliente.query.get_or_404(idcliente)

        if claims["perfilid"] != 0 and cliente.idcliente != claims["idcliente"]:
            return jsonify({"error": "No autorizado"}), 403

        data = request.get_json() or {}
        for field in [
            "nombre","nit","email","pais","ciudad","direccion","telefono1","logo_url"
        ]:
            if field in data:
                setattr(cliente, field, data[field])

        if "activo" in data:
            cliente.activo = bool(data["activo"])

        if "limite_usuarios" in data:
            cliente.limite_usuarios = int(data["limite_usuarios"]) if data["limite_usuarios"] not in ("", None) else None
        if "limite_sesiones" in data:
            cliente.limite_sesiones = int(data["limite_sesiones"]) if data["limite_sesiones"] not in ("", None) else None

        db.session.commit()
        return jsonify(cliente.as_dict())


    @app.route("/clientes/<int:idcliente>", methods=["DELETE"])
    @jwt_required()
    def delete_cliente(idcliente):
        claims = get_jwt()
        if claims["perfilid"] != 0:
            return jsonify({"error": "No autorizado"}), 403

        cliente = Cliente.query.get_or_404(idcliente)
        db.session.delete(cliente)
        db.session.commit()
        return jsonify({"message": "Cliente eliminado"})


    # ==========================
    # SuperAdmin CRUD Perfiles
    # ==========================
    @app.route("/admin/perfiles", methods=["GET"])
    @jwt_required()
    def admin_get_perfiles():
        claims = get_jwt()
        if claims["perfilid"] == 0:  # SuperAdmin → puede ver todos
            perfiles = Perfil.query.all()
        else:
            perfiles = Perfil.query.filter_by(idcliente=claims["idcliente"]).all()
        return jsonify([p.as_dict() for p in perfiles])

    @app.route("/admin/perfiles", methods=["POST"])
    @jwt_required()
    def admin_crear_perfil():
        claims = get_jwt()
        if claims["perfilid"] != 0:  
            return jsonify({"error": "No autorizado"}), 403

        data = request.get_json()
        perfil = Perfil(
            idcliente=data["idcliente"],   # 👑 SuperAdmin puede decidir a qué cliente asignarlo
            nombre=data["nombre"],
            descripcion=data.get("descripcion", "")
        )
        db.session.add(perfil)
        db.session.commit()
        return jsonify(perfil.as_dict()), 201

    @app.route("/admin/perfiles/<int:idperfil>", methods=["PUT"])
    @jwt_required()
    def admin_update_perfil(idperfil):
        claims = get_jwt()
        if claims["perfilid"] != 0:
            return jsonify({"error": "No autorizado"}), 403

        perfil = Perfil.query.get_or_404(idperfil)
        data = request.get_json()
        perfil.nombre = data.get("nombre", perfil.nombre)
        perfil.descripcion = data.get("descripcion", perfil.descripcion)
        db.session.commit()
        return jsonify(perfil.as_dict())

    @app.route("/admin/perfiles/<int:idperfil>", methods=["DELETE"])
    @jwt_required()
    def admin_delete_perfil(idperfil):
        claims = get_jwt()
        if claims["perfilid"] != 0:
            return jsonify({"error": "No autorizado"}), 403

        perfil = Perfil.query.get_or_404(idperfil)
        db.session.delete(perfil)
        db.session.commit()
        return jsonify({"message": "Perfil eliminado"})


    # ==========================
    # Superadmin CRUD Usuarios
    # ==========================
    @app.route("/admin/usuarios", methods=["GET"])
    @jwt_required()
    def admin_get_usuarios():
        claims = get_jwt()
        if claims["perfilid"] != 0:  
            return jsonify({"error": "No autorizado"}), 403
        usuarios = Usuario.query.all()
        return jsonify([u.as_dict() for u in usuarios])

    @app.route("/admin/usuarios", methods=["POST"])
    @jwt_required()
    def admin_crear_usuario():
        claims = get_jwt()
        if claims["perfilid"] != 0:
            return jsonify({"error": "No autorizado"}), 403

        data = request.get_json() or {}
        user = Usuario(
            idcliente=data["idcliente"],
            idperfil=data["idperfil"],
            nombre=data["nombre"],
            apellido=data.get("apellido"),  # NUEVO
            email=data["email"],
            password_hash=generate_password_hash(data["password"], method="pbkdf2:sha256"),
            activo=True
        )
        db.session.add(user)
        db.session.commit()
        return jsonify(user.as_dict()), 201


    @app.route("/admin/usuarios/<int:idusuario>", methods=["PUT"])
    @jwt_required()
    def admin_update_usuario(idusuario):
        claims = get_jwt()
        if claims["perfilid"] != 0:
            return jsonify({"error": "No autorizado"}), 403
        user = Usuario.query.get_or_404(idusuario)
        data = request.get_json() or {}
        for field in ["nombre","apellido","email","idcliente","idperfil","activo"]:
            if field in data:
                setattr(user, field, data[field])
        if "password" in data and data["password"]:
            user.password_hash = generate_password_hash(data["password"], method="pbkdf2:sha256")
        db.session.commit()
        return jsonify(user.as_dict())

    @app.route("/admin/usuarios/<int:idusuario>", methods=["DELETE"])
    @jwt_required()
    def admin_delete_usuario(idusuario):
        claims = get_jwt()
        if claims["perfilid"] != 0:
            return jsonify({"error": "No autorizado"}), 403
        user = Usuario.query.get_or_404(idusuario)
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "Usuario eliminado"})


    # ==========================
    # Registro Inicial de Cliente por el superadmin
    # ==========================

    @app.route("/clientes/registro_inicial", methods=["POST"])
    @jwt_required()
    def registro_inicial_cliente():
        claims = get_jwt()
        if claims["perfilid"] != 0:  # Solo SuperAdmin puede hacerlo
            return jsonify({"error": "No autorizado"}), 403

        data = request.get_json()

        # 1️⃣ Crear Cliente
        cliente = Cliente(
            nombre=data["cliente"]["nombre"],
            nit=data["cliente"].get("nit"),
            email=data["cliente"].get("email"),
            activo=True
        )
        db.session.add(cliente)
        db.session.flush()  # Para obtener idcliente antes de commit

        # 2️⃣ Crear Perfil Administrador
        perfil_admin = Perfil(
            idcliente=cliente.idcliente,
            nombre="Administrador",
            descripcion="Perfil administrador del cliente"
        )
        db.session.add(perfil_admin)
        db.session.flush()

        # 3️⃣ Crear Usuario Administrador
        password_hash = generate_password_hash(
            data["usuario"]["password"], method="pbkdf2:sha256", salt_length=16
        )
        usuario_admin = Usuario(
            idcliente=cliente.idcliente,
            idperfil=perfil_admin.idperfil,
            nombre=data["usuario"]["nombre"],
            email=data["usuario"]["email"],
            password_hash=password_hash,
            activo=True
        )
        db.session.add(usuario_admin)
        db.session.commit()

        return jsonify({
            "cliente": cliente.as_dict(),
            "perfil_admin": {
                "idperfil": perfil_admin.idperfil,
                "nombre": perfil_admin.nombre
            },
            "usuario_admin": {
                "idusuario": usuario_admin.idusuario,
                "email": usuario_admin.email,
                "nombre": usuario_admin.nombre
            }
        }), 201

    # ==========================
    # Cliente Admin CRUD Perfiles
    # ==========================
    @app.route("/perfiles", methods=["POST"])
    @jwt_required()
    def cliente_crear_perfil():
        claims = get_jwt()
        if claims["perfilid"] == 0:  
            return jsonify({"error": "SuperAdmin no puede crear perfiles de clientes"}), 403

        data = request.get_json()
        perfil = Perfil(
            idcliente=claims["idcliente"],  # 🔐 siempre el cliente del token
            nombre=data["nombre"],
            descripcion=data.get("descripcion", "")
        )
        db.session.add(perfil)
        db.session.commit()
        return jsonify(perfil.as_dict()), 201

    @app.route("/perfiles/<int:idperfil>", methods=["PUT"])
    @jwt_required()
    def cliente_update_perfil(idperfil):
        claims = get_jwt()
        if claims["perfilid"] == 0:  
            return jsonify({"error": "SuperAdmin no puede editar perfiles de clientes"}), 403

        perfil = Perfil.query.get_or_404(idperfil)
        if perfil.idcliente != claims["idcliente"]:
            return jsonify({"error": "No autorizado"}), 403

        data = request.get_json()
        perfil.nombre = data.get("nombre", perfil.nombre)
        perfil.descripcion = data.get("descripcion", perfil.descripcion)
        db.session.commit()
        return jsonify(perfil.as_dict())

    @app.route("/perfiles/<int:idperfil>", methods=["DELETE"])
    @jwt_required()
    def cliente_delete_perfil(idperfil):
        claims = get_jwt()
        if claims["perfilid"] == 0:
            return jsonify({"error": "SuperAdmin no puede borrar perfiles de clientes"}), 403

        perfil = Perfil.query.get_or_404(idperfil)
        if perfil.idcliente != claims["idcliente"]:
            return jsonify({"error": "No autorizado"}), 403

        db.session.delete(perfil)
        db.session.commit()
        return jsonify({"message": "Perfil eliminado"})


    # ==========================
    # Cliente Admin CRUD Usuarios
    # ==========================

    @app.route("/usuarios", methods=["POST"])
    @jwt_required()
    def crear_usuario():
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        perfilid = claims.get("perfilid")

        # 🔐 Solo admins de cliente pueden crear usuarios
        if perfilid == 0:
            return jsonify({"error": "SuperAdmin no puede crear usuarios de clientes"}), 403

        data = request.get_json()
        perfil = Perfil.query.filter_by(idperfil=data["idperfil"], idcliente=idcliente).first()
        if not perfil:
            return jsonify({"error": "Perfil no válido para este cliente"}), 400

        password_hash = generate_password_hash(
            data["password"], method="pbkdf2:sha256", salt_length=16
        )
        usuario = Usuario(
            idcliente=idcliente,
            idperfil=perfil.idperfil,
            nombre=data["nombre"],
            email=data["email"],
            password_hash=password_hash,
            activo=True
        )
        db.session.add(usuario)
        db.session.commit()

        return jsonify({
            "idusuario": usuario.idusuario,
            "nombre": usuario.nombre,
            "email": usuario.email,
            "perfil": perfil.nombre
        }), 201



    @app.route("/usuarios/<int:idusuario>", methods=["PUT"])
    @jwt_required()
    def cliente_update_usuario(idusuario):
        claims = get_jwt()
        if claims["perfilid"] == 0:  
            return jsonify({"error": "SuperAdmin no debe usar este endpoint"}), 403

        usuario = Usuario.query.get_or_404(idusuario)
        if usuario.idcliente != claims["idcliente"]:
            return jsonify({"error": "No autorizado"}), 403

        data = request.get_json()
        usuario.nombre = data.get("nombre", usuario.nombre)
        usuario.email = data.get("email", usuario.email)
        if "password" in data:
            usuario.password_hash = generate_password_hash(data["password"], method="pbkdf2:sha256")
        db.session.commit()
        return jsonify(usuario.as_dict())


    @app.route("/usuarios/<int:idusuario>", methods=["DELETE"])
    @jwt_required()
    def cliente_delete_usuario(idusuario):
        claims = get_jwt()
        if claims["perfilid"] == 0:  
            return jsonify({"error": "SuperAdmin no debe usar este endpoint"}), 403

        usuario = Usuario.query.get_or_404(idusuario)
        if usuario.idcliente != claims["idcliente"]:
            return jsonify({"error": "No autorizado"}), 403

        db.session.delete(usuario)
        db.session.commit()
        return jsonify({"message": "Usuario eliminado"})


    # Consulta de usuarios por cliente Admin
    @app.route("/usuarios", methods=["GET"])
    @jwt_required()
    def cliente_listar_usuarios():
        claims = get_jwt()
        if claims["perfilid"] == 0:
            return jsonify({"error": "SuperAdmin no debe usar este endpoint"}), 403
        idcliente = claims.get("idcliente")
        usuarios = Usuario.query.filter_by(idcliente=idcliente).all()
        return jsonify([u.as_dict() for u in usuarios])


    # para que el frontend consulte el rol y el cliente del token
    @app.route("/auth/whoami", methods=["GET"])
    @jwt_required()
    def whoami():
        user_id = get_jwt_identity()
        user = Usuario.query.get(user_id)
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404

        data = {
            "idusuario": user.idusuario,
            "idcliente": user.idcliente,
            "idperfil": user.idperfil,
            "perfilid": 0 if user.idcliente is None else user.idperfil,
            "email": user.email,
        }

        if user.idcliente:
            cliente = Cliente.query.get(user.idcliente)
            if cliente:
                data["cliente"] = {
                    "id": cliente.idcliente,
                    "nombre": cliente.nombre,
                    "logo_url": cliente.logo_url,
                }

        return jsonify(data), 200


    @app.route("/config/siigo", methods=["GET"])
    @jwt_required()
    def get_siigo_config():
        claims = get_jwt()
        perfilid = claims["perfilid"]
        idcliente = claims.get("idcliente")

        # superadmin puede inspeccionar otro cliente
        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0:
            if not q_idcliente:
                return jsonify({"error": "Falta idcliente"}), 400
            idcliente = q_idcliente
        else:
            if not idcliente:
                return jsonify({"error": "No autorizado"}), 403

        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg:
            return jsonify({
                "idcliente": idcliente,
                "base_url": None,
                "client_id": None,
                "client_secret_mask": None,
                "username": None,
                "password_mask": None,
                "updated_at": None
            })

        # Enmascara secretos
        def mask(s: str | None):
            if not s: return None
            return s[:2] + "•"*(max(0, len(s)-4)) + s[-2:]

        return jsonify({
            "idcliente": idcliente,
            "base_url": cfg.base_url,
            "client_id": cfg.client_id,
            "client_secret_mask": mask(dec(cfg.client_secret)),
            "username": cfg.username,
            "password_mask": mask(dec(cfg.password)),
            "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None
        })


    @app.route("/config/siigo", methods=["PUT"])
    @jwt_required()
    def upsert_siigo_config():
        claims = get_jwt()
        perfilid = claims["perfilid"]
        idcliente = claims.get("idcliente")

        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0:
            if not q_idcliente:
                return jsonify({"error": "Falta idcliente"}), 400
            idcliente = q_idcliente
        else:
            if not idcliente:
                return jsonify({"error": "No autorizado"}), 403

        data = request.get_json() or {}
        base_url = data.get("base_url")
        client_id = data.get("client_id")
        client_secret = data.get("client_secret")  # texto plano, opcional
        username = data.get("username")
        password = data.get("password")            # texto plano, opcional

        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg:
            cfg = SiigoCredencial(idcliente=idcliente)

        if base_url is not None: cfg.base_url = base_url
        if client_id is not None: cfg.client_id = client_id
        if client_secret: cfg.client_secret = enc(client_secret)
        if username is not None: cfg.username = username
        if password: cfg.password = enc(password)

        db.session.add(cfg)
        db.session.commit()
        return jsonify({"message": "Configuración guardada"}), 200



    @app.route("/siigo/test_auth", methods=["POST"])
    @jwt_required()
    def siigo_test_auth():
        """
        Autenticación contra Siigo:
        - Flujo recomendado: JSON POST /auth con {"username","access_key"} y Partner-Id obligatorio.
        - Si eso no responde 200/401/404, probamos variantes.
        """
        claims = get_jwt()
        perfilid = claims["perfilid"]
        idcliente = claims.get("idcliente")

        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0:
            if not q_idcliente:
                return jsonify({"ok": False, "error": "Falta idcliente"}), 400
            idcliente = q_idcliente
        else:
            if not idcliente:
                return jsonify({"ok": False, "error": "No autorizado"}), 403

        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg or not cfg.base_url or not cfg.client_id or not cfg.client_secret:
            return jsonify({"ok": False, "error": "Credenciales incompletas"}), 400

        base_url = (cfg.base_url or "").rstrip("/")
        username = cfg.client_id or ""                 # tu “Usuario API”, ej: correo
        access_key = dec(cfg.client_secret) or ""      # tu Access Key (tal cual)
        partner_id = os.getenv("SIIGO_PARTNER_ID", PARTNER_ID_DEFAULT).strip() or PARTNER_ID_DEFAULT

        # Headers base SIEMPRE con Partner-Id
        base_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Partner-Id": partner_id,
        }

        timeout = 60

        # 1) Flujo JSON (oficial)
        json_auth_urls = [
            f"{base_url}/auth",
            f"{base_url}/v1/auth",
            f"{base_url}/oauth2/token",
        ]
        for url in json_auth_urls:
            try:
                r = requests.post(
                    url,
                    headers=base_headers,
                    json={"username": username, "access_key": access_key},
                    timeout=timeout,
                )
                if r.status_code == 200:
                    data = {}
                    try: data = r.json()
                    except Exception: pass
                    return jsonify({
                        "ok": True,
                        "flow": "json",
                        "endpoint": url,
                        "token_type": data.get("token_type"),
                        "expires_in": data.get("expires_in"),
                    }), 200

                if r.status_code in (401, 403):
                    return jsonify({
                        "ok": False,
                        "flow": "json",
                        "endpoint": url,
                        "error": f"Credenciales inválidas ({r.status_code})",
                        "body": r.text[:800],
                    }), r.status_code

                if r.status_code == 404:
                    # probamos siguiente variante
                    continue

                return jsonify({
                    "ok": False,
                    "flow": "json",
                    "endpoint": url,
                    "error": f"HTTP {r.status_code}",
                    "body": r.text[:800],
                }), 502
            except requests.RequestException as e:
                return jsonify({
                    "ok": False,
                    "flow": "json",
                    "endpoint": url,
                    "error": f"Conexión fallida: {str(e)}",
                }), 502

        # 2) Variantes BASIC (por si tu tenant tuviera esa exigencia)
        pair = f"{username}:{access_key}"
        basic_token = base64.b64encode(pair.encode("utf-8")).decode("utf-8")
        basic_headers = dict(base_headers)
        basic_headers["Authorization"] = f"Basic {basic_token}"

        basic_urls = [
            f"{base_url}/auth",
            f"{base_url}/v1/auth",
            f"{base_url}/oauth2/token",
        ]
        for url in basic_urls:
            try:
                r = requests.post(url, headers=basic_headers, timeout=timeout)
                if r.status_code == 200:
                    data = {}
                    try: data = r.json()
                    except Exception: pass
                    return jsonify({
                        "ok": True,
                        "flow": "basic",
                        "endpoint": url,
                        "token_type": data.get("token_type"),
                        "expires_in": data.get("expires_in"),
                    }), 200

                if r.status_code in (401, 403):
                    return jsonify({
                        "ok": False,
                        "flow": "basic",
                        "endpoint": url,
                        "error": f"Credenciales inválidas ({r.status_code})",
                        "body": r.text[:800],
                    }), r.status_code

                if r.status_code == 404:
                    continue

                return jsonify({
                    "ok": False,
                    "flow": "basic",
                    "endpoint": url,
                    "error": f"HTTP {r.status_code}",
                    "body": r.text[:800],
                }), 502
            except requests.RequestException as e:
                return jsonify({
                    "ok": False,
                    "flow": "basic",
                    "endpoint": url,
                    "error": f"Conexión fallida: {str(e)}",
                }), 502

        return jsonify({
            "ok": False,
            "error": "No se encontró un endpoint de auth que responda correctamente.",
            "tried_json": json_auth_urls,
            "tried_basic": basic_urls,
            "partner_id_used": partner_id,
            "base_url_used": base_url,
        }), 502


    # (Opcional) Endpoint de diagnóstico rápido
    @app.route("/siigo/_diag", methods=["GET"])
    @jwt_required()
    def siigo_diag():
        claims = get_jwt()
        perfilid = claims["perfilid"]
        idcliente = claims.get("idcliente")
        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0 and q_idcliente:
            idcliente = q_idcliente

        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        partner_id = os.getenv("SIIGO_PARTNER_ID", PARTNER_ID_DEFAULT).strip() or PARTNER_ID_DEFAULT
        return jsonify({
            "idcliente": idcliente,
            "base_url": (cfg.base_url if cfg else None),
            "client_id": (cfg.client_id if cfg else None),
            "secret_stored": bool(cfg and cfg.client_secret),
            "partner_id": partner_id,
        })


    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)

