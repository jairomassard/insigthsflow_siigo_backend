from sqlalchemy import func
from flask import Flask, jsonify, request, current_app
from flask import send_file
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt, get_jwt_identity, decode_token,
    verify_jwt_in_request  # 👈 agrega esto
)
from flask_cors import cross_origin
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import date, datetime, timezone, timedelta
 
from config import Config
from models import db, Usuario, Cliente, Perfil, SesionActiva, SiigoCredencial, SiigoFactura, SiigoFacturaItem, SiigoVendedor, SiigoCentroCosto, SiigoCustomer, SiigoNotaCredito, SiigoPagoProveedor, SiigoProveedor, SiigoCompra, SiigoCompraItem, SiigoCuentasPorCobrar, SiigoNomina, SiigoProducto, BalancePrueba, Permiso, PerfilPermiso, SiigoSyncConfig, SiigoSyncLog, SiigoSyncMetric, SystemNotification
from flask_cors import CORS
import os
from cryptography.fernet import Fernet, InvalidToken
import base64, json, requests

from flask_jwt_extended import jwt_required, get_jwt
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request


from siigo_api import auth as siigo_auth, SiigoError
from siigo.siigo_sync_refactor import sync_facturas_desde_siigo
from datetime import datetime
import requests
from siigo.siigo_sync_refactor import _request_with_retries, _str, siigo_auth_json, _headers_bearer, dec_local, contar_facturas_pendientes
from siigo.siigo_sync_pagos import sync_pagos_egresos_desde_siigo
from siigo.siigo_sync_compras import sync_compras_desde_siigo
from sqlalchemy import text, func
from utils import _siigo_headers_bearer, _siigo_auth_json_for_client

from io import BytesIO
import pandas as pd
import zipfile

import requests
import time


from sqlalchemy.sql import text
import math

import unicodedata
from sqlalchemy.dialects.postgresql import insert

from openpyxl import load_workbook
# 👇 Importa también los helpers de seguridad
from decoradores_seguridad import (
    permiso_requerido,
    _is_superadmin,
    _perfil_tiene_permiso
)

from utils import local_to_utc, utc_to_local


import threading
from threading import Thread
import traceback


FERNET_KEY = os.environ.get("APP_CRYPTO_KEY")  # genera una vez y guárdala en .env
fernet = Fernet(FERNET_KEY) if FERNET_KEY else None

#PARTNER_ID_DEFAULT = "ProjectManagerApp"
PARTNER_ID_DEFAULT = os.getenv("SIIGO_PARTNER_ID", "ProjectManagerApp")
AUTH_TIMEOUT_SEC = int(os.getenv("SIIGO_AUTH_TIMEOUT", "60"))
SANDBOX = os.getenv("SIIGO_SANDBOX", "0") == "1"

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


# --- Función utilitaria compartida por /reportes/analisis_clientes y por  /reportes/facturas_cliente ---
def enriquecer_facturas(rows):
    today = date.today()
    enriched = []

    for r in rows:
        dias = None
        estado = "sano"

        # Asegurar campo pendiente
        pendiente = r.get("pendiente", r.get("saldo", 0)) or 0
        try:
            pendiente = float(pendiente)
        except Exception:
            pendiente = 0

        if round(pendiente, 2) == 0:
            estado = "pagado"
        else:
            venc = r.get("vencimiento")
            if venc:
                venc_dt = venc if isinstance(venc, date) else date.fromisoformat(str(venc))
                dias = (venc_dt - today).days
                if dias < 0:
                    estado = "vencido"
                elif dias <= 5:
                    estado = "alerta"
                else:
                    estado = "sano"

        r["dias_vencimiento"] = dias
        r["estado_cartera"] = estado
        enriched.append(r)

    return enriched


def quitar_tildes(texto):
    if not texto:
        return texto
    return ''.join(
        c for c in unicodedata.normalize('NFD', texto)
        if unicodedata.category(c) != 'Mn'
    )



def interpretar_indicador(k: str, v: float | None) -> str:
    if v is None:
        return "Sin datos suficientes para interpretar."

    match k:
        case "liquidez":
            if v < 1:
                return "Riesgo de iliquidez: activo corriente insuficiente."
            elif v <= 3:
                return "Saludable: puede cubrir obligaciones a corto plazo."
            else:
                return "Exceso de liquidez: posible ineficiencia de capital."
        case "apalancamiento":
            if v > 0.8:
                return "Endeudamiento alto: activos financiados en su mayoría por deuda."
            elif v > 0.6:
                return "Nivel de endeudamiento moderado."
            else:
                return "Apalancamiento controlado: estructura sana."
        case "rentabilidad":
            if v < 0:
                return "Rentabilidad negativa: pérdidas netas."
            elif v < 0.1:
                return "Rentabilidad positiva pero baja."
            else:
                return "Rentabilidad sólida sobre ingresos."
        case "solvencia":
            if v < 1:
                return "Solvencia deficiente: activos no cubren pasivos."
            elif v <= 2:
                return "Solvencia adecuada: activos cubren deudas."
            else:
                return "Solvencia muy alta: estructura sólida."
        case "autonomia":
            if v < 0:
                return "Patrimonio negativo: dependencia total de deuda."
            elif v < 0.3:
                return "Alta dependencia del financiamiento externo."
            else:
                return "Buena autonomía financiera."
        case "endeudamiento_largo_plazo":
            if v <= 0:
                return "No interpretable (patrimonio negativo o nulo)."
            elif v > 1:
                return "Presión financiera a largo plazo elevada."
            else:
                return "Estructura de deuda a largo plazo saludable."
        case "capital_trabajo":
            if v < 0:
                return "Capital de trabajo negativo: riesgo operativo."
            elif v == 0:
                return "Capital de trabajo neutro."
            else:
                return "Colchón operativo positivo."
        case "cobertura_activo_pasivo":
            if v < 1:
                return "Activos insuficientes para cubrir pasivos."
            elif v <= 2:
                return "Cobertura aceptable de pasivos."
            else:
                return "Alta cobertura de pasivos: buena estructura."
        case "porcentaje_activo_no_corriente":
            if v > 0.7:
                return "Alta proporción de activos no líquidos."
            elif v > 0.4:
                return "Balance adecuado entre activos líquidos y fijos."
            else:
                return "Predominio de activos líquidos."
        case "porcentaje_pasivo_corto":
            if v > 0.7:
                return "Alta carga de pasivos a corto plazo."
            elif v > 0.4:
                return "Distribución equilibrada de pasivos."
            else:
                return "Predominio de deuda a largo plazo."
        case _:
            return "Sin interpretación disponible."




def obtener_idcliente_desde_request():
    """
    Obtiene el ID del cliente necesario para todas las sincronizaciones.
    Primero intenta el header 'X-ID-CLIENTE'. Si no existe, intenta extraerlo del JWT.
    """

    # 1. Intentar header primero
    x_id = request.headers.get("X-ID-CLIENTE")
    if x_id:
        print("obtener_idcliente_desde_request: desde header →", x_id)
        try:
            return int(x_id)
        except ValueError:
            return None

    # 2. Si no hay header, intentar JWT opcional
    try:
        verify_jwt_in_request(optional=True)  # 👈 aquí el truco
        identity = get_jwt_identity()
        if identity and isinstance(identity, dict):
            idc = identity.get("idcliente")
            print("obtener_idcliente_desde_request: desde JWT →", idc)
            if idc is not None:
                return int(idc)
    except Exception as e:
        print("obtener_idcliente_desde_request: error al leer JWT:", e)

    print("obtener_idcliente_desde_request: no se encontró idcliente")
    return None



def create_app():
    app = Flask(__name__, static_folder="static", static_url_path="")

    app.config.from_object(Config)

    # app.py (o donde configuras Flask/JWT)
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "pon-una-clave-larga-y-estable")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 60 * 60 * 24  # 24h opcional


    # ✅ CORS en la instancia CORRECTA
    # CORS aplicado globalmente con soporte completo
    CORS(
        app,
        resources={r"/*": {
            "origins": "https://insigthsflow.up.railway.app",
            "allow_headers": ["Content-Type", "Authorization", "X-ID-CLIENTE"],
            "supports_credentials": True
        }}
    )

    print("🔍 Usando esta URI de base de datos:", app.config["SQLALCHEMY_DATABASE_URI"])
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
            timezone=data.get("timezone", "America/Bogota")  # 👈 nuevo campo con valor por defecto
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
            "nombre","nit","email","pais","ciudad","direccion","telefono1","logo_url", "timezone"
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


    @app.route("/clientes/<int:idcliente>/full_delete", methods=["DELETE"])
    @jwt_required()
    def delete_cliente_total(idcliente):
        """
        Elimina por completo un cliente y toda su data relacionada.
        Requiere doble confirmación:
        - 1ra: el modal en el frontend
        - 2da: el parámetro ?confirm=true en la URL
        Solo SuperAdmin puede ejecutar esta acción.
        """
        claims = get_jwt()
        if claims["perfilid"] != 0:
            return jsonify({"error": "No autorizado"}), 403

        # Confirmación requerida
        confirm = request.args.get("confirm", "false").lower()
        if confirm != "true":
            return jsonify({
                "warning": "⚠️ Falta confirmación final. "
                        "Para eliminar definitivamente, agrega '?confirm=true' al endpoint.",
                "example": f"/clientes/{idcliente}/full_delete?confirm=true"
            }), 400

        cliente = Cliente.query.get_or_404(idcliente)

        modelos_relacionados = [
            Usuario,
            Perfil,
            Permiso,
            PerfilPermiso,
            SesionActiva,
            SiigoCredencial,
            SiigoFactura,
            SiigoFacturaItem,
            SiigoVendedor,
            SiigoCentroCosto,
            SiigoCustomer,
            SiigoNotaCredito,
            SiigoPagoProveedor,
            SiigoCompra,
            SiigoCompraItem,
            SiigoProveedor,
            SiigoCuentasPorCobrar,
            SiigoNomina,
            SiigoProducto,
            BalancePrueba,
        ]

        resumen = {}
        for modelo in modelos_relacionados:
            count = modelo.query.filter_by(idcliente=idcliente).delete(synchronize_session=False)
            resumen[modelo.__tablename__] = count

        db.session.delete(cliente)
        db.session.commit()

        return jsonify({
            "message": f"✅ Cliente '{cliente.nombre}' y toda su información fueron eliminados correctamente.",
            "detalles": resumen
        }), 200




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

        # 3️⃣ Clonar permisos base del cliente 1
        permisos_base = Permiso.query.filter_by(idcliente=1).all()
        for p in permisos_base:
            nuevo = Permiso(
                idcliente=cliente.idcliente,
                nombre=p.nombre,
                codigo=p.codigo,
                descripcion=p.descripcion,
                activo=p.activo
            )
            db.session.add(nuevo)
        db.session.flush()

        # 4️⃣ Asignar todos los permisos al perfil administrador del nuevo cliente
        for nuevo_permiso in Permiso.query.filter_by(idcliente=cliente.idcliente).all():
            rel = PerfilPermiso(
                idcliente=cliente.idcliente,
                idperfil=perfil_admin.idperfil,
                idpermiso=nuevo_permiso.idpermiso,
                permitido=True
            )
            db.session.add(rel)

        # 5️⃣ Crear Usuario Administrador
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
            apellido=data.get("apellido"),
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
        usuario.apellido = data.get("apellido", usuario.apellido)
        usuario.email = data.get("email", usuario.email)

        if "password" in data and data["password"]:
            usuario.password_hash = generate_password_hash(
                data["password"], method="pbkdf2:sha256", salt_length=16
            )
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
        user = db.session.get(Usuario, user_id)
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
            cliente = db.session.get(Cliente, user.idcliente)
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
                "partner_id": None,
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
            "partner_id": cfg.partner_id,
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
        partner_id = data.get("partner_id")

        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg:
            cfg = SiigoCredencial(idcliente=idcliente)

        if base_url is not None: cfg.base_url = base_url
        if client_id is not None: cfg.client_id = client_id
        if client_secret: cfg.client_secret = enc(client_secret)
        if username is not None: cfg.username = username
        if password: cfg.password = enc(password)
        if partner_id is not None: cfg.partner_id = partner_id

        db.session.add(cfg)
        db.session.commit()
        return jsonify({"message": "Configuración guardada"}), 200



    @app.route("/siigo/test_auth", methods=["POST"])
    @jwt_required()
    def siigo_test_auth():
        """
        Autenticación contra Siigo con dos flujos (JSON y Basic).
        Si SIIGO_SANDBOX=1 (o ?force_sandbox=1), responde OK sin llamar a Siigo.
        """
        # -------- sandbox / simulación ----------
        force_sandbox = request.args.get("force_sandbox") == "1"
        if SANDBOX or force_sandbox:
            return jsonify({
                "ok": True,
                "flow": "sandbox",
                "endpoint": None,
                "token_type": "bearer",
                "expires_in": 3600
            }), 200
        # ----------------------------------------

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
        username = cfg.client_id or ""                 # Usuario API (correo)
        access_key = dec(cfg.client_secret) or ""      # Access Key
        partner_id = os.getenv("SIIGO_PARTNER_ID", PARTNER_ID_DEFAULT).strip() or PARTNER_ID_DEFAULT

        base_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Partner-Id": partner_id,
        }

        timeout = AUTH_TIMEOUT_SEC

        # ---------- 1) Flujo JSON (oficial) ----------
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
                    try:
                        data = r.json() or {}
                        print("=== TOKEN DE SIIGO ===")
                        print(data)
                    except Exception:
                        data = {}
                    return jsonify({
                        "ok": True,
                        "flow": "json",
                        "endpoint": url,
                        "token_type": data.get("token_type"),
                        "expires_in": data.get("expires_in"),
                        "access_token": data.get("access_token")  # 👈 para que aparezca en respuesta
                    }), 200

                if r.status_code in (401, 403):
                    return jsonify({
                        "ok": False,
                        "flow": "json",
                        "endpoint": url,
                        "error": f"Credenciales inválidas ({r.status_code})",
                        "body": (r.text or "")[:800],
                    }), r.status_code

                if r.status_code == 404:
                    # probar siguiente variante
                    continue

                return jsonify({
                    "ok": False,
                    "flow": "json",
                    "endpoint": url,
                    "error": f"HTTP {r.status_code}",
                    "body": (r.text or "")[:800],
                }), 502
            except requests.RequestException as e:
                return jsonify({
                    "ok": False,
                    "flow": "json",
                    "endpoint": url,
                    "error": f"Conexión fallida: {str(e)}",
                }), 502

        # ---------- 2) Flujo Basic (fallback) ----------
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
                    try:
                        data = r.json() or {}
                    except Exception:
                        data = {}
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
                        "body": (r.text or "")[:800],
                    }), r.status_code

                if r.status_code == 404:
                    continue

                return jsonify({
                    "ok": False,
                    "flow": "basic",
                    "endpoint": url,
                    "error": f"HTTP {r.status_code}",
                    "body": (r.text or "")[:800],
                }), 502
            except requests.RequestException as e:
                return jsonify({
                    "ok": False,
                    "flow": "basic",
                    "endpoint": url,
                    "error": f"Conexión fallida: {str(e)}",
                }), 502

        # ---------- ninguna ruta respondió ----------
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

        if cfg and cfg.client_secret:
            try:
                access_key = dec(cfg.client_secret)
            except Exception as e:
                access_key = f"ERROR: {e}"
        else:
            access_key = None

        print("DEBUG auth credentials:")
        print("  Username:", cfg.client_id if cfg else "❌ no cfg")
        print("  Access Key:", access_key or "❌ vacía")

        return jsonify({
            "idcliente": idcliente,
            "base_url": (cfg.base_url if cfg else None),
            "client_id": (cfg.client_id if cfg else None),
            "secret_stored": bool(cfg and cfg.client_secret),
            "partner_id": partner_id,
        })
        



    @app.route("/siigo/sync-facturas", methods=["POST"])
    def siigo_sync_facturas():
        idcliente = obtener_idcliente_desde_request()
        if not idcliente:
            return jsonify({"error": "Cliente no autorizado"}), 403

        deep = request.args.get("deep") in ("1", "true", "yes")
        batch = request.args.get("batch", default=None, type=int)
        only_missing = request.args.get("only_missing", default="1") in ("1", "true", "yes")
        since = request.args.get("since")
        modo_sync_all = request.headers.get("X-SYNC-ALL") == "1"  # 👈 marca que viene desde /sync-all

        kwargs = {
            "idcliente": idcliente,
            "deep": deep,
            "only_missing": only_missing,
            "since": since,
        }
        if batch:
            kwargs["batch_size"] = batch

        try:
            if modo_sync_all:
                # 🔹 Ejecución sin background (sincrónica)
                mensaje = sync_facturas_desde_siigo(**kwargs)
                return jsonify({"mensaje": mensaje}), 200
            else:
                # 🔹 Ejecución background para UI manual
                def trabajo_lento(local_kwargs):
                    with app.app_context():
                        try:
                            mensaje = sync_facturas_desde_siigo(**local_kwargs)
                            print(f"[siigo_sync_facturas] ✅ Terminado: {mensaje}")
                        except Exception:
                            traceback.print_exc()

                t = Thread(target=trabajo_lento, args=(kwargs,), daemon=True)
                t.start()
                return jsonify({"mensaje": "Sincronización iniciada en background. Revisar logs para progreso."}), 202
        except Exception as e:
            return jsonify({"error": str(e)}), 500




    @app.route("/siigo/debug-invoice", methods=["GET"])
    @jwt_required()
    def siigo_debug_invoice():
        """
        Muestra:
        - detalle crudo de Siigo para una factura (por ?uuid=... o ?name=...)
        - lo guardado en siigo_facturas y siigo_factura_items
        Uso:
        /siigo/debug-invoice?uuid=<uuid_de_siigo>
        /siigo/debug-invoice?name=<name/FV-...>
        Nota: requiere JWT; usa el idcliente del token (o ?idcliente= en superadmin).
        """
        claims = get_jwt()
        perfilid = claims.get("perfilid")
        idcliente = claims.get("idcliente")

        # superadmin puede inspeccionar otro cliente
        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0 and q_idcliente:
            idcliente = q_idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado o sin cliente en el token"}), 403

        uuid = request.args.get("uuid", type=str)
        name = request.args.get("name", type=str)
        if not uuid and not name:
            return jsonify({"error": "Proporciona ?uuid= o ?name="}), 400

        # cargar credenciales
        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg or not cfg.base_url or not cfg.client_id or not cfg.client_secret:
            return jsonify({"error": "Credenciales de Siigo no configuradas para este cliente"}), 400

        # autenticar
        auth_data = _siigo_auth_json_for_client(cfg)
        if auth_data.get("_error"):
            return jsonify({"error": auth_data["_error"]}), 502
        token = auth_data.get("access_token")
        if not token:
            return jsonify({"error": "No se obtuvo access_token desde Siigo"}), 502

        base_url = (cfg.base_url or "").rstrip("/")
        headers = _siigo_headers_bearer(token)

        # 1) Traer detalle crudo desde Siigo
        raw_detail = None
        tried = []
        try:
            if uuid:
                url = f"{base_url}/v1/invoices/{uuid}"
                tried.append(url)
                r = requests.get(url, headers=headers, timeout=60)
                if r.status_code == 200:
                    raw_detail = r.json()
                elif name:
                    # fallback por nombre si mandaste también name
                    url2 = f"{base_url}/v1/invoices/{name}"
                    tried.append(url2)
                    r2 = requests.get(url2, headers=headers, timeout=60)
                    if r2.status_code == 200:
                        raw_detail = r2.json()
                    else:
                        # búsqueda por query name
                        url3 = f"{base_url}/v1/invoices?name={name}"
                        tried.append(url3)
                        r3 = requests.get(url3, headers=headers, timeout=60)
                        if r3.status_code == 200:
                            payload = r3.json() or {}
                            res = payload.get("results") or []
                            raw_detail = res[0] if res else None
            else:
                # sólo name
                url = f"{base_url}/v1/invoices/{name}"
                tried.append(url)
                r = requests.get(url, headers=headers, timeout=60)
                if r.status_code == 200:
                    raw_detail = r.json()
                else:
                    url2 = f"{base_url}/v1/invoices?name={name}"
                    tried.append(url2)
                    r2 = requests.get(url2, headers=headers, timeout=60)
                    if r2.status_code == 200:
                        payload = r2.json() or {}
                        res = payload.get("results") or []
                        raw_detail = res[0] if res else None
        except requests.RequestException as e:
            return jsonify({"error": f"Error consultando Siigo: {str(e)}", "tried": tried}), 502

        # 2) Lo que tienes guardado en BD
        factura_db = None
        items_db = []
        if name:
            factura_db = SiigoFactura.query.filter_by(idcliente=idcliente, idfactura=name).first()
        elif uuid:
            factura_db = SiigoFactura.query.filter_by(idcliente=idcliente, siigo_uuid=uuid).first()
            # si no la encuentra por uuid, intenta por name si el detalle lo trae
            if not factura_db and raw_detail and isinstance(raw_detail, dict):
                nm = raw_detail.get("name")
                if nm:
                    factura_db = SiigoFactura.query.filter_by(idcliente=idcliente, idfactura=nm).first()

        if factura_db:
            items_db = SiigoFacturaItem.query.filter_by(factura_id=factura_db.id).all()

        # 3) Serializar para JSON (sin SQLAlchemy-automagic)
        def _dec(v):
            # helper simple: para Decimals/fechas
            from decimal import Decimal
            if isinstance(v, Decimal):
                return float(v)
            if isinstance(v, (datetime, )):
                return v.isoformat()
            return v

        def factura_to_dict(f):
            if not f:
                return None
            return {
                "id": f.id,
                "idcliente": f.idcliente,
                "idfactura": f.idfactura,
                "siigo_uuid": f.siigo_uuid,
                "fecha": f.fecha.isoformat() if f.fecha else None,
                "vencimiento": f.vencimiento.isoformat() if f.vencimiento else None,
                "cliente_nombre": f.cliente_nombre,
                "vendedor": f.vendedor,
                "seller_id": f.seller_id,
                "estado": f.estado,
                "total": _dec(f.total),
                "saldo": _dec(f.saldo),
                "subtotal": _dec(f.subtotal),
                "impuestos_total": _dec(f.impuestos_total),
                "descuentos_total": _dec(f.descuentos_total),
                "pagos_total": _dec(f.pagos_total),
                "saldo_calculado": _dec(f.saldo_calculado),
                "estado_pago": f.estado_pago,
                "moneda": f.moneda,
                "medio_pago": f.medio_pago,
                "observaciones": f.observaciones,
                "metadata_created": f.metadata_created.isoformat() if f.metadata_created else None,
                "metadata_updated": f.metadata_updated.isoformat() if f.metadata_updated else None,
                "created_at": f.created_at.isoformat() if f.created_at else None,
                "customer_id": f.customer_id,
                "customer_identificacion": f.customer_identificacion,
            }

        def item_to_dict(it):
            return {
                "id": it.id,
                "factura_id": it.factura_id,
                "descripcion": it.descripcion,
                "cantidad": _dec(it.cantidad),
                "precio": _dec(it.precio),
                "impuestos": _dec(it.impuestos),
                "producto_id": it.producto_id,
                "codigo": it.codigo,
                "sku": it.sku,
                "iva_porcentaje": _dec(it.iva_porcentaje),
                "iva_valor": _dec(it.iva_valor),
                "descuento_valor": _dec(it.descuento_valor),
                "total_item": _dec(it.total_item),
            }

        resp = {
            "query_params": {"uuid": uuid, "name": name, "idcliente": idcliente},
            "siigo_tried_urls": tried,
            "siigo_raw_detail": raw_detail,  # <- lo crudo que devuelve Siigo (tal cual)
            "db_factura": factura_to_dict(factura_db),
            "db_items": [item_to_dict(i) for i in items_db],
        }
        return jsonify(resp), 200



    # Sincronización de vendedores y de centros de costos
    @app.route("/siigo/sync-catalogos", methods=["POST"])

    def siigo_sync_catalogos():
        idcliente = obtener_idcliente_desde_request()
        if not idcliente:
            return jsonify({"error": "Cliente no autorizado"}), 403

        cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cred:
            return jsonify({"error": "Credenciales no encontradas"}), 400

        access_key = dec(cred.client_secret)
        if not access_key:
            return jsonify({"error": "No se pudo desencriptar access_key"}), 400

        try:
            token_data = siigo_auth_json(cred.base_url, cred.client_id, access_key)
            token = token_data["access_token"]
            headers = _headers_bearer(token)

            # -------------------------
            # Sync vendedores
            # -------------------------
            r_v = _request_with_retries("GET", f"{cred.base_url.rstrip('/')}/v1/users", headers=headers)
            if r_v.status_code == 200:
                db.session.query(SiigoVendedor).filter_by(idcliente=idcliente).delete(synchronize_session=False)

                payload = r_v.json()

                # puede ser lista o dict con results
                if isinstance(payload, list):
                    results = payload
                else:
                    results = payload.get("results", [])

                for u in results:
                    vid = u.get("id")
                    nombre = _str(
                        u.get("name")
                        or u.get("full_name")
                        or u.get("display_name")
                        or f"{u.get('first_name','')} {u.get('last_name','')}".strip()
                    )
                    if vid:
                        db.session.add(SiigoVendedor(
                            id=vid,
                            idcliente=idcliente,  # ← Este campo es clave
                            nombre=nombre,
                            activo=bool(u.get("active", True)),
                            metadata_json=u
                        ))

            # -------------------------
            # Sync centros de costo
            # -------------------------
            r_cc = _request_with_retries("GET", f"{cred.base_url.rstrip('/')}/v1/cost-centers", headers=headers)
            if r_cc.status_code == 200:
                db.session.query(SiigoCentroCosto).filter_by(idcliente=idcliente).delete(synchronize_session=False)

                payload = r_cc.json()

                # puede ser lista o dict con results
                if isinstance(payload, list):
                    results = payload
                else:
                    results = payload.get("results", [])

                for c in results:
                    cid = c.get("id")
                    nombre = _str(c.get("name") or c.get("description") or c.get("code"))
                    if cid:
                        db.session.add(SiigoCentroCosto(
                            id=cid,
                            idcliente=idcliente,  # ✅ Obligatorio después del cambio
                            nombre=nombre,
                            codigo=_str(c.get("code")),
                            activo=bool(c.get("active", True)),
                            metadata_json=c
                        ))

            db.session.commit()
            return jsonify({"mensaje": "Catálogos sincronizados correctamente"}), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500


    # ------------------------------------------
    # Catálogo de Vendedores
    # ------------------------------------------
    @app.route("/catalogos/vendedores", methods=["GET"])
    @jwt_required()
    def get_catalogo_vendedores():
        claims = get_jwt()
        perfilid = claims["perfilid"]
        idcliente = claims.get("idcliente")

        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0 and q_idcliente:
            idcliente = q_idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        try:
            vendedores = SiigoVendedor.query.all()
            data = [
                {
                    "id": v.id,
                    "nombre": v.nombre,
                    "activo": v.activo,
                }
                for v in vendedores
            ]
            return jsonify(data), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500


    # ------------------------------------------
    # Catálogo de Centros de Costo
    # ------------------------------------------
    @app.route("/catalogos/centros-costo/general", methods=["GET"])
    @jwt_required()
    def get_catalogo_centros_costo():
        claims = get_jwt()
        perfilid = claims["perfilid"]
        idcliente = claims.get("idcliente")

        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0 and q_idcliente:
            idcliente = q_idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        try:
            centros = SiigoCentroCosto.query.all()
            data = [
                {
                    "id": c.id,
                    "nombre": c.nombre,
                    "codigo": c.codigo,
                    "activo": c.activo,
                }
                for c in centros
            ]
            return jsonify(data), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500


    # Sincronización de clientes (terceros) desde Siigo
    @app.route("/siigo/sync-customers", methods=["POST"])
    
    def siigo_sync_customers():
        idcliente = obtener_idcliente_desde_request()
        if not idcliente:
            return jsonify({"error": "Cliente no autorizado"}), 403

        cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cred:
            return jsonify({"error": "Credenciales no encontradas"}), 400

        access_key = dec(cred.client_secret)
        if not access_key:
            return jsonify({"error": "No se pudo desencriptar access_key"}), 400

        try:
            token_data = siigo_auth_json(cred.base_url, cred.client_id, access_key)
            token = token_data["access_token"]
            headers = _headers_bearer(token)

            base_url = cred.base_url.rstrip("/")
            page = 1
            page_size = 100
            total_insertados = 0

            # limpiar tabla antes de insertar
            db.session.query(SiigoCustomer).filter_by(idcliente=idcliente).delete()

            while True:
                url = f"{base_url}/v1/customers?page={page}&page_size={page_size}"
                r = _request_with_retries("GET", url, headers=headers)
                if r.status_code != 200:
                    break

                payload = r.json()
                results = []
                if isinstance(payload, list):
                    results = payload
                else:
                    results = payload.get("results", [])

                if not results:
                    break

                for c in results:
                    cid = c.get("id")
                    if not cid:
                        continue
                    sc = SiigoCustomer(
                        id=cid,
                        idcliente=idcliente,
                        identification=c.get("identification"),
                        name=c.get("name"),
                        first_name=c.get("first_name"),
                        last_name=c.get("last_name"),
                        branch_office=c.get("branch_office"),
                        email=(c.get("email") if isinstance(c.get("email"), str) else None),
                        phone=(c.get("phone") if isinstance(c.get("phone"), str) else None),
                        address=c.get("address"),
                        contacts=c.get("contacts"),
                        metadata_json=c,
                    )
                    db.session.add(sc)
                    total_insertados += 1

                # ¿hay más páginas?
                links = payload.get("_links", {}) if isinstance(payload, dict) else {}
                if not links.get("next") or not links["next"].get("href"):
                    break

                page += 1

            db.session.commit()
            return jsonify({"mensaje": f"Clientes sincronizados: {total_insertados}"}), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500



    # ==========================
    # Reportes y Dashboards 
    # ==========================


    # Endpoint reporte Financiero (con KPIs + series)

    @app.route("/reportes/facturas_enriquecidas", methods=["GET"])
    @jwt_required()
    def get_facturas_enriquecidas():
        claims = get_jwt()
        perfilid = claims.get("perfilid")
        idcliente = claims.get("idcliente")

        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0 and q_idcliente:
            idcliente = q_idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        desde       = request.args.get("desde")
        hasta       = request.args.get("hasta")
        seller_id   = request.args.get("seller_id", type=int)
        cost_center = request.args.get("cost_center", type=int)
        cliente     = request.args.get("cliente")
        limit       = request.args.get("limit", type=int) or 5000

        try:
            wh = ["f.idcliente = :idcliente"]
            params = {"idcliente": idcliente, "limit": limit}
            if desde:
                wh.append("f.fecha >= :desde")
                params["desde"] = desde
            if hasta:
                wh.append("f.fecha <= :hasta")
                params["hasta"] = hasta
            if seller_id:
                wh.append("f.seller_id = :seller_id")
                params["seller_id"] = seller_id
            if cost_center:
                wh.append("f.cost_center = :cost_center")
                params["cost_center"] = cost_center
            if cliente:
                wh.append("f.cliente_nombre = :cliente")
                params["cliente"] = cliente

            where_clause = " AND ".join(wh)

            # ---- Rows
            sql_rows = text(f"""
                SELECT DISTINCT ON (f.id)
                    f.id              AS factura_id,
                    f.idcliente,
                    f.idfactura,
                    f.fecha,
                    f.vencimiento,
                    f.cliente_nombre  AS cliente_nombre,
                    f.estado,
                    f.estado_pago,
                    f.subtotal,
                    f.impuestos_total,
                    f.total,
                    f.pagos_total,
                    f.saldo,
                    f.saldo_calculado,
                    f.medio_pago,
                    f.observaciones,
                    f.public_url,
                    f.cost_center,
                    COALESCE(cc.nombre, 'Sin centro de costo') AS centro_costo_nombre,
                    cc.codigo AS centro_costo_codigo,
                    f.seller_id,
                    v.nombre AS vendedor_nombre
                FROM siigo_facturas f
                LEFT JOIN siigo_vendedores   v  ON f.seller_id   = v.id
                LEFT JOIN siigo_centros_costo cc ON f.cost_center = cc.id
                LEFT JOIN siigo_customers     c  ON f.customer_id = c.id
                                                AND f.idcliente   = c.idcliente
                WHERE {where_clause}
                ORDER BY f.id DESC
                LIMIT :limit
            """)
            rows = [dict(r) for r in db.session.execute(sql_rows, params).mappings().all()]

            # ---------- KPIs / series ----------
            cte_common = f"""
                WITH comp AS (
                    SELECT
                        f.*,
                        -- Autorretención
                        COALESCE((
                            SELECT SUM((elem->>'value')::numeric)
                            FROM jsonb_array_elements(f.retenciones) elem
                            WHERE jsonb_typeof(f.retenciones) = 'array'
                            AND LOWER(elem->>'type') LIKE '%autorretencion%'
                        ), 0) AS autorretencion,
                        -- Retenciones sin autorretención
                        COALESCE((
                            SELECT SUM((elem->>'value')::numeric)
                            FROM jsonb_array_elements(f.retenciones) elem
                            WHERE jsonb_typeof(f.retenciones) = 'array'
                            AND (elem->>'type') IS NOT NULL
                            AND LOWER(elem->>'type') NOT LIKE '%autorretencion%'
                        ), 0) AS retenciones_sin_auto,
                        COALESCE(f.total, 0) AS total_b,
                        COALESCE(f.saldo, 0) AS saldo_b
                    FROM facturas_enriquecidas f
                    WHERE {where_clause}
                ),
                ajuste AS (
                    SELECT
                        date_trunc('month', fecha) AS mes,
                        subtotal,
                        impuestos_total,
                        autorretencion,
                        retenciones_sin_auto,
                        total_b,
                        saldo_b,
                        total_b AS total_facturado,
                        (total_b - (autorretencion + retenciones_sin_auto)) AS total_utilizable,
                        (total_b - saldo_b) AS pagado,
                        saldo_b AS pendiente
                    FROM comp
                )
            """

            # KPIs
            sql_kpis = text(cte_common + """
                SELECT
                    COALESCE(SUM(subtotal), 0)              AS subtotal,
                    COALESCE(SUM(impuestos_total), 0)       AS impuestos,
                    COALESCE(SUM(autorretencion), 0)        AS autorretencion,
                    COALESCE(SUM(total_facturado), 0)       AS total_facturado,
                    COALESCE(SUM(retenciones_sin_auto), 0)  AS retenciones,
                    COALESCE(SUM(total_utilizable), 0)      AS total_utilizable,
                    COALESCE(SUM(pagado), 0)                AS pagado,
                    COALESCE(SUM(pendiente), 0)             AS pendiente
                FROM ajuste
            """)
            kpis = dict(db.session.execute(sql_kpis, params).mappings().first() or {})

            # Series
            sql_series = text(cte_common + """
                SELECT
                    TO_CHAR(mes, 'Mon YYYY')                 AS label,
                    COALESCE(SUM(subtotal), 0)              AS subtotal,
                    COALESCE(SUM(impuestos_total), 0)       AS impuestos,
                    COALESCE(SUM(autorretencion), 0)        AS autorretencion,
                    COALESCE(SUM(total_facturado), 0)       AS total_facturado,
                    COALESCE(SUM(retenciones_sin_auto), 0)  AS retenciones,
                    COALESCE(SUM(total_utilizable), 0)      AS total_utilizable,
                    COALESCE(SUM(pagado), 0)                AS pagado,
                    COALESCE(SUM(pendiente), 0)             AS pendiente
                FROM ajuste
                GROUP BY mes
                ORDER BY MIN(mes)
            """)
            series = [dict(r) for r in db.session.execute(sql_series, params).mappings().all()]

            # Estados (pie)
            sql_estados = text(cte_common + """
                SELECT 'Pagado' AS estado,   COALESCE(SUM(pagado), 0)    AS valor FROM ajuste
                UNION ALL
                SELECT 'Pendiente',          COALESCE(SUM(pendiente), 0) AS valor FROM ajuste
            """)
            estados = [dict(r) for r in db.session.execute(sql_estados, params).mappings().all()]

            # Top clientes
            sql_top_clientes = text(f"""
                SELECT 
                    f.cliente_nombre AS cliente,
                    COALESCE(SUM(f.total), 0) AS total
                FROM facturas_enriquecidas f
                WHERE {where_clause}
                GROUP BY f.cliente_nombre
                ORDER BY total DESC
                LIMIT 5
            """)
            top_clientes = [dict(r) for r in db.session.execute(sql_top_clientes, params).mappings().all()]

            return jsonify({
                "rows": rows,
                "kpis": kpis,
                "series": series,
                "estados": estados,
                "top_clientes": top_clientes,
                "count": len(rows)
            })

        except Exception as e:
            return jsonify({"error": str(e)}), 500



    @app.route("/catalogos/clientes-facturas", methods=["GET"])
    @jwt_required()
    def catalogo_clientes_facturas():
        claims = get_jwt()
        idcliente = claims.get("idcliente")

        q_idcliente = request.args.get("idcliente", type=int)
        if claims.get("perfilid") == 0 and q_idcliente:
            idcliente = q_idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")

        try:
            wh = ["f.idcliente = :idcliente"]
            params = {"idcliente": idcliente}
            if desde:
                wh.append("f.fecha >= :desde")
                params["desde"] = desde
            if hasta:
                wh.append("f.fecha <= :hasta")
                params["hasta"] = hasta
            where_clause = " AND ".join(wh)

            sql = text(f"""
                SELECT DISTINCT
                    f.cliente_nombre AS id,
                    f.cliente_nombre AS nombre
                FROM facturas_enriquecidas f
                WHERE {where_clause}
                AND TRIM(COALESCE(f.cliente_nombre, '')) <> ''
                ORDER BY nombre
            """)
            rows = [dict(r) for r in db.session.execute(sql, params).mappings().all()]
            return jsonify(rows)


        except Exception as e:
            return jsonify({"error": str(e)}), 500


    @app.route("/siigo/sync-pendientes", methods=["GET"])
    @jwt_required()
    def contar_pendientes():
        idcliente = get_jwt_identity()
        cantidad = contar_facturas_pendientes(idcliente)
        return jsonify({"pendientes": cantidad})



    # --- ENDPOINT: Clientes Insights (enriquecido) --- 
    @app.route("/reportes/analisis_clientes", methods=["GET"])
    @jwt_required()
    def get_clientes_insights():
        claims = get_jwt()
        perfilid = claims.get("perfilid")
        idcliente = claims.get("idcliente")

        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0 and q_idcliente:
            idcliente = q_idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        desde       = request.args.get("desde")
        hasta       = request.args.get("hasta")
        cliente     = request.args.get("cliente")  # filtro por cliente opcional
        cost_center = request.args.get("cost_center", type=int)
        filtro_estado = request.args.get("estado")  # 👈 mismo que en facturas_cliente

        try:
            wh = ["f.idcliente = :idcliente"]
            params = {"idcliente": idcliente}

            if desde:
                wh.append("f.fecha >= :desde")
                params["desde"] = desde
            if hasta:
                wh.append("f.fecha <= :hasta")
                params["hasta"] = hasta
            if cliente:
                wh.append("LOWER(TRIM(f.cliente_nombre)) = LOWER(TRIM(:cliente))")
                params["cliente"] = cliente
            if cost_center:
                wh.append("f.cost_center = :cost_center")
                params["cost_center"] = cost_center

            where_clause = " AND ".join(wh)

            # --- KPIs por cliente
            sql_clientes = text(f"""
                SELECT
                    f.cliente_nombre AS cliente,
                    COUNT(*) AS cantidad_facturas,
                    COALESCE(SUM(f.total), 0) AS total_facturado,
                    COALESCE(SUM(f.total - f.saldo), 0) AS total_pagado,
                    COALESCE(SUM(f.saldo), 0) AS saldo_pendiente
                FROM facturas_enriquecidas f
                WHERE {where_clause}
                GROUP BY f.cliente_nombre
                ORDER BY total_facturado DESC
            """)
            clientes = [dict(r) for r in db.session.execute(sql_clientes, params).mappings().all()]

            # --- Centros de costo por cliente
            sql_cc = text(f"""
                SELECT
                    f.cliente_nombre,
                    COALESCE(cc.nombre, 'Sin centro de costo') AS centro_costo_nombre,
                    f.cost_center,
                    COUNT(*) AS cantidad_facturas,
                    COALESCE(SUM(f.total), 0) AS total_facturado,
                    COALESCE(SUM(f.total - f.saldo), 0) AS total_pagado,
                    COALESCE(SUM(f.saldo), 0) AS saldo_pendiente
                FROM facturas_enriquecidas f
                LEFT JOIN siigo_centros_costo cc
                ON f.cost_center = cc.id
                WHERE {where_clause}
                GROUP BY f.cliente_nombre, f.cost_center, cc.nombre
                ORDER BY total_facturado DESC
            """)
            centros_costo = [dict(r) for r in db.session.execute(sql_cc, params).mappings().all()]

            # --- Facturas recientes (máx 5 por cliente)
            sql_facturas = text(f"""
                WITH ranked AS (
                    SELECT
                        f.idfactura,
                        f.fecha,
                        f.vencimiento,
                        f.total,
                        (f.total - f.saldo) AS pagado,
                        f.saldo AS pendiente,
                        f.public_url,
                        f.cliente_nombre,
                        ROW_NUMBER() OVER (PARTITION BY f.cliente_nombre ORDER BY f.fecha DESC) AS rn
                    FROM facturas_enriquecidas f
                    WHERE {where_clause}
                )
                SELECT * FROM ranked WHERE rn <= 5;
            """)
            rows = [dict(r) for r in db.session.execute(sql_facturas, params).mappings().all()]
            enriched = enriquecer_facturas(rows)

            # aplicar filtro de estado si corresponde
            if filtro_estado:
                enriched = [r for r in enriched if r["estado_cartera"] == filtro_estado.lower()]

            # --- Conteo de facturas por estado (agrupado por cliente)
            sql_estados = text(f"""
                SELECT
                    f.cliente_nombre,
                    f.idfactura,
                    f.fecha,
                    f.vencimiento,
                    f.total,
                    f.saldo
                FROM facturas_enriquecidas f
                WHERE {where_clause}
            """)
            rows_estado = [dict(r) for r in db.session.execute(sql_estados, params).mappings().all()]
            # Normalizar campo para enriquecer correctamente
            for r in rows_estado:
                r["pendiente"] = r.get("saldo", 0)

            enriched_estados = enriquecer_facturas(rows_estado)

            facturas_por_estado = {}
            for r in enriched_estados:
                cliente = r["cliente_nombre"]
                estado = r["estado_cartera"]

                if cliente not in facturas_por_estado:
                    facturas_por_estado[cliente] = {}

                facturas_por_estado[cliente][estado] = facturas_por_estado[cliente].get(estado, 0) + 1

            # Convertir a lista [{cliente, estado, cantidad}, ...]
            facturas_por_estado_list = []
            for cliente, estados in facturas_por_estado.items():
                for estado, cantidad in estados.items():
                    facturas_por_estado_list.append({
                        "cliente": cliente,
                        "estado": estado,
                        "cantidad": cantidad
                    })

            return jsonify({
                "clientes": clientes,
                "centros_costo": centros_costo,
                "facturas_recientes": enriched,
                "facturas_por_estado": facturas_por_estado_list  # 👈 ya viene separado por cliente
            })

        except Exception as e:
            return jsonify({"error": str(e)}), 500



    # --- ENDPOINT: Facturas por cliente/centro de costo (paginadas) ---
    @app.route("/reportes/facturas_cliente", methods=["GET"])
    @jwt_required()
    def get_facturas_cliente():
        claims = get_jwt()
        perfilid = claims.get("perfilid")
        idcliente = claims.get("idcliente")

        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0 and q_idcliente:
            idcliente = q_idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        desde       = request.args.get("desde")
        hasta       = request.args.get("hasta")
        cliente     = request.args.get("cliente")
        cost_center = request.args.get("cost_center", type=int)
        limit       = request.args.get("limit", type=int) or 20
        offset      = request.args.get("offset", type=int) or 0
        filtro_estado = request.args.get("estado")  # 👈 'sano' | 'alerta' | 'vencido' | 'pagado'

        try:
            wh = ["f.idcliente = :idcliente"]
            params = {"idcliente": idcliente, "limit": limit, "offset": offset}

            if desde:
                wh.append("f.fecha >= :desde")
                params["desde"] = desde
            if hasta:
                wh.append("f.fecha <= :hasta")
                params["hasta"] = hasta
            if cliente:
                wh.append("LOWER(TRIM(f.cliente_nombre)) = LOWER(TRIM(:cliente))")
                params["cliente"] = cliente
            if cost_center:
                wh.append("f.cost_center = :cost_center")
                params["cost_center"] = cost_center

            where_clause = " AND ".join(wh)

            sql = text(f"""
                SELECT
                    f.idfactura,
                    f.fecha,
                    f.vencimiento,
                    f.total,
                    (f.total - f.saldo) AS pagado,
                    f.saldo AS pendiente,
                    f.public_url,
                    f.cliente_nombre,
                    COALESCE(f.centro_costo_nombre, 'Sin centro de costo') AS centro_costo_nombre
                FROM facturas_enriquecidas f
                WHERE {where_clause}
                ORDER BY f.fecha DESC
                LIMIT :limit OFFSET :offset
            """)
            rows = [dict(r) for r in db.session.execute(sql, params).mappings().all()]
            enriched = enriquecer_facturas(rows)

            # aplicar filtro de estado si corresponde
            if filtro_estado:
                enriched = [r for r in enriched if r["estado_cartera"] == filtro_estado.lower()]

            return jsonify({"rows": enriched})

        except Exception as e:
            return jsonify({"error": str(e)}), 500



    # --- ENDPOINT: Catálogo de centros de costo ---
    @app.route("/catalogos/centros-costo", methods=["GET"])
    @jwt_required()
    def catalogo_centros_costo():
        claims = get_jwt()
        idcliente = claims.get("idcliente")

        q_idcliente = request.args.get("idcliente", type=int)
        if claims.get("perfilid") == 0 and q_idcliente:
            idcliente = q_idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")

        try:
            wh = ["f.idcliente = :idcliente"]
            params = {"idcliente": idcliente}

            if desde:
                wh.append("f.fecha >= :desde")
                params["desde"] = desde
            if hasta:
                wh.append("f.fecha <= :hasta")
                params["hasta"] = hasta

            where_clause = " AND ".join(wh)

            sql = text(f"""
                SELECT DISTINCT
                    f.cost_center AS id,
                    COALESCE(cc.nombre, 'Sin centro de costo') AS nombre
                FROM facturas_enriquecidas f
                LEFT JOIN siigo_centros_costo cc ON f.cost_center = cc.id
                WHERE {where_clause}
                AND f.cost_center IS NOT NULL
                ORDER BY nombre
            """)
            rows = [dict(r) for r in db.session.execute(sql, params).mappings().all()]
            return jsonify(rows)

        except Exception as e:
            return jsonify({"error": str(e)}), 500



    # --- ENDPOINT: Sincronizar notas crédito desde Siigo ---
    @app.route("/siigo/sync-notas-credito", methods=["POST"])
    
    def siigo_sync_notas_credito():
        idcliente = obtener_idcliente_desde_request()
        if not idcliente:
            return jsonify({"error": "Cliente no autorizado"}), 403

        try:
            cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
            if not cred or not cred.client_id or not cred.client_secret or not cred.base_url:
                return jsonify({"error": "Credenciales de Siigo no configuradas"}), 400

            access_key = dec(cred.client_secret)
            if not access_key:
                return jsonify({"error": "No se pudo desencriptar el Access Key"}), 400

            token_data = siigo_auth_json(cred.base_url, cred.client_id, access_key)
            token = token_data.get("access_token")
            if not token:
                return jsonify({"error": "Error al obtener token Siigo"}), 500

            page = 1
            nuevas, actualizadas = 0, 0
            while True:
                url = f"{cred.base_url.rstrip('/')}/v1/credit-notes?page={page}&page_size=100"
                r = _request_with_retries("GET", url, headers=_headers_bearer(token))
                if r.status_code != 200:
                    return jsonify({"error": f"Siigo error {r.status_code}: {r.text}"}), r.status_code
                data = r.json() or {}
                notas = data.get("results") or []
                if not notas:
                    break

                for n in notas:
                    nota_id = _str(n.get("name"))
                    if not nota_id:
                        continue

                    fecha_str = n.get("date")
                    try:
                        fecha = datetime.fromisoformat(fecha_str).date() if fecha_str else None
                    except Exception:
                        fecha = None

                    total = float(n.get("total") or 0)
                    estado = _str(n.get("status"))
                    observaciones = _str(n.get("observations"))
                    motivo = _str(n.get("reason"))
                    uuid = _str(n.get("id"))
                    customer = n.get("customer") or {}
                    cliente_nombre = _str(customer.get("name"))
                    customer_id = _str(customer.get("id"))

                    factura_afectada_id = _str((n.get("invoice") or {}).get("name"))
                    factura_afectada_uuid = _str((n.get("invoice") or {}).get("id"))
                    metadata_json = n  # guarda el JSON completo

                    # Buscar si ya existe por nota_id
                    nota = SiigoNotaCredito.query.filter_by(idcliente=idcliente, nota_id=nota_id).first()
                    if nota:
                        changes = 0
                        if nota.fecha != fecha: nota.fecha = fecha; changes += 1
                        if nota.total != total: nota.total = total; changes += 1
                        if nota.estado != estado: nota.estado = estado; changes += 1
                        if nota.observaciones != observaciones: nota.observaciones = observaciones; changes += 1
                        if nota.motivo != motivo: nota.motivo = motivo; changes += 1
                        if nota.uuid != uuid: nota.uuid = uuid; changes += 1
                        if nota.cliente_nombre != cliente_nombre: nota.cliente_nombre = cliente_nombre; changes += 1
                        if nota.customer_id != customer_id: nota.customer_id = customer_id; changes += 1
                        if nota.factura_afectada_id != factura_afectada_id: nota.factura_afectada_id = factura_afectada_id; changes += 1
                        if nota.factura_afectada_uuid != factura_afectada_uuid: nota.factura_afectada_uuid = factura_afectada_uuid; changes += 1
                        if nota.metadata_json != metadata_json: nota.metadata_json = metadata_json; changes += 1

                        if changes > 0:
                            actualizadas += 1
                    else:
                        nota = SiigoNotaCredito(
                            idcliente=idcliente,
                            nota_id=nota_id,
                            fecha=fecha,
                            total=total,
                            estado=estado,
                            observaciones=observaciones,
                            motivo=motivo,
                            uuid=uuid,
                            cliente_nombre=cliente_nombre,
                            customer_id=customer_id,
                            factura_afectada_id=factura_afectada_id,
                            factura_afectada_uuid=factura_afectada_uuid,
                            metadata_json=metadata_json,
                        )
                        db.session.add(nota)
                        nuevas += 1

                db.session.commit()

                next_href = ((data.get("_links") or {}).get("next") or {}).get("href")
                if not next_href or len(notas) < 100:
                    break
                page += 1

            return jsonify({
                "mensaje": f"Sincronización de notas crédito completa: {nuevas} nuevas, {actualizadas} actualizadas.",
                "total_procesadas": nuevas + actualizadas
            })

        except Exception as e:
            return jsonify({"error": str(e)}), 500


    # --- ENDPOINT: Debug de una Nota Crédito ---
    @app.route("/siigo/debug-nota-credito", methods=["GET"])
    @jwt_required()
    def siigo_debug_nota_credito():
        """
        Muestra:
        - detalle crudo de Siigo para una nota crédito (por ?uuid=... o ?name=...)
        - lo guardado en siigo_notas_credito
        Uso:
        /siigo/debug-nota-credito?uuid=<uuid_de_siigo>
        /siigo/debug-nota-credito?name=<name/NC-...>
        Nota: requiere JWT; usa el idcliente del token (o ?idcliente= en superadmin).
        """
        claims = get_jwt()
        perfilid = claims.get("perfilid")
        idcliente = claims.get("idcliente")

        # superadmin puede inspeccionar otro cliente
        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0 and q_idcliente:
            idcliente = q_idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado o sin cliente en el token"}), 403

        uuid = request.args.get("uuid", type=str)
        name = request.args.get("name", type=str)
        if not uuid and not name:
            return jsonify({"error": "Proporciona ?uuid= o ?name="}), 400

        # cargar credenciales
        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg or not cfg.base_url or not cfg.client_id or not cfg.client_secret:
            return jsonify({"error": "Credenciales de Siigo no configuradas para este cliente"}), 400

        # autenticar
        auth_data = _siigo_auth_json_for_client(cfg)
        if auth_data.get("_error"):
            return jsonify({"error": auth_data["_error"]}), 502
        token = auth_data.get("access_token")
        if not token:
            return jsonify({"error": "No se obtuvo access_token desde Siigo"}), 502

        base_url = (cfg.base_url or "").rstrip("/")
        headers = _siigo_headers_bearer(token)

        # 1) Traer detalle crudo desde Siigo
        raw_detail = None
        tried = []
        try:
            if uuid:
                url = f"{base_url}/v1/credit-notes/{uuid}"
                tried.append(url)
                r = requests.get(url, headers=headers, timeout=60)
                if r.status_code == 200:
                    raw_detail = r.json()
                elif name:
                    url2 = f"{base_url}/v1/credit-notes/{name}"
                    tried.append(url2)
                    r2 = requests.get(url2, headers=headers, timeout=60)
                    if r2.status_code == 200:
                        raw_detail = r2.json()
                    else:
                        url3 = f"{base_url}/v1/credit-notes?name={name}"
                        tried.append(url3)
                        r3 = requests.get(url3, headers=headers, timeout=60)
                        if r3.status_code == 200:
                            payload = r3.json() or {}
                            res = payload.get("results") or []
                            raw_detail = res[0] if res else None
            else:
                url = f"{base_url}/v1/credit-notes/{name}"
                tried.append(url)
                r = requests.get(url, headers=headers, timeout=60)
                if r.status_code == 200:
                    raw_detail = r.json()
                else:
                    url2 = f"{base_url}/v1/credit-notes?name={name}"
                    tried.append(url2)
                    r2 = requests.get(url2, headers=headers, timeout=60)
                    if r2.status_code == 200:
                        payload = r2.json() or {}
                        res = payload.get("results") or []
                        raw_detail = res[0] if res else None
        except requests.RequestException as e:
            return jsonify({"error": f"Error consultando Siigo: {str(e)}", "tried": tried}), 502

        # 2) Lo que tienes guardado en BD
        nota_db = None
        if name:
            nota_db = SiigoNotaCredito.query.filter_by(idcliente=idcliente, nota_id=name).first()
        elif uuid:
            nota_db = SiigoNotaCredito.query.filter_by(idcliente=idcliente, uuid=uuid).first()
            if not nota_db and raw_detail and isinstance(raw_detail, dict):
                nm = raw_detail.get("name")
                if nm:
                    nota_db = SiigoNotaCredito.query.filter_by(idcliente=idcliente, nota_id=nm).first()

        # 3) Serializar para JSON
        def _dec(v):
            from decimal import Decimal
            if isinstance(v, Decimal):
                return float(v)
            if isinstance(v, (datetime, )):
                return v.isoformat()
            return v

        def nota_to_dict(n):
            if not n:
                return None
            return {
                "id": n.id,
                "idcliente": n.idcliente,
                "nota_id": n.nota_id,
                "uuid": n.uuid,
                "fecha": n.fecha.isoformat() if n.fecha else None,
                "total": _dec(n.total),
                "estado": n.estado,
                "motivo": n.motivo,
                "observaciones": n.observaciones,
                "cliente_nombre": n.cliente_nombre,
                "customer_id": n.customer_id,
                "factura_afectada_id": n.factura_afectada_id,
                "metadata_json": n.metadata_json,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }

        resp = {
            "query_params": {"uuid": uuid, "name": name, "idcliente": idcliente},
            "siigo_tried_urls": tried,
            "siigo_raw_detail": raw_detail,   # <- lo crudo que devuelve Siigo
            "db_nota_credito": nota_to_dict(nota_db),
        }
        return jsonify(resp), 200



    # --- ENDPOINT: Reporte de Cuentas por Cobrar (Aging Report) ---
    @app.route("/reportes/cuentas-por-cobrar", methods=["GET"])
    @jwt_required()
    def cuentas_por_cobrar():
        """
        Reporte Aging (Cuentas por Cobrar).
        Devuelve:
        - resumen_global (totales, % vencido, etc.)
        - consolidado por cliente / centro costo / vendedor (fusionado por nombre limpio).
        - detalle de facturas (si ?detalle=1).
        - proyeccion_por_fecha: vencimientos diarios con facturas asociadas.
        """

        from collections import defaultdict

        def normalizar_cliente(nombre: str) -> str:
            return (nombre or "").strip().lower().replace(".", "").replace(",", "")

        claims = get_jwt()
        perfilid = claims.get("perfilid")
        idcliente = claims.get("idcliente")

        # Superadmin puede inspeccionar otro cliente
        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0 and q_idcliente:
            idcliente = q_idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado o sin cliente en el token"}), 403

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        incluir_detalle = request.args.get("detalle", "0") == "1"

        condiciones = ["idcliente = :idcliente", "saldo > 0"]
        params = {"idcliente": idcliente}

        if desde:
            condiciones.append("fecha >= :desde")
            params["desde"] = desde
        if hasta:
            condiciones.append("fecha <= :hasta")
            params["hasta"] = hasta

        where_sql = " AND ".join(condiciones)

        # --- Query base (consolidado) ---
        query_base = f"""
            SELECT
                cliente_nombre,
                centro_costo_nombre,
                vendedor_nombre,
                COUNT(*) AS num_facturas,
                SUM(saldo) AS saldo_total,
                SUM(CASE WHEN CURRENT_DATE <= vencimiento THEN saldo ELSE 0 END) AS saldo_sano,
                SUM(CASE WHEN CURRENT_DATE > vencimiento AND CURRENT_DATE - vencimiento <= 30 THEN saldo ELSE 0 END) AS saldo_1_30,
                SUM(CASE WHEN CURRENT_DATE - vencimiento BETWEEN 31 AND 60 THEN saldo ELSE 0 END) AS saldo_31_60,
                SUM(CASE WHEN CURRENT_DATE - vencimiento BETWEEN 61 AND 90 THEN saldo ELSE 0 END) AS saldo_61_90,
                SUM(CASE WHEN CURRENT_DATE - vencimiento > 90 THEN saldo ELSE 0 END) AS saldo_mas_90
            FROM facturas_enriquecidas
            WHERE {where_sql}
            GROUP BY cliente_nombre, centro_costo_nombre, vendedor_nombre
            ORDER BY saldo_total DESC
        """
        result = db.session.execute(text(query_base), params).mappings().all()
        rows_raw = [dict(r) for r in result]

        # Agrupar por nombre normalizado
        agrupado = defaultdict(list)
        for r in rows_raw:
            clave = normalizar_cliente(r["cliente_nombre"])
            agrupado[clave].append(r)

        # Fusionar datos
        consolidado = []
        for grupo in agrupado.values():
            base = grupo[0].copy()
            base["aging"] = {
                "por_vencer": float(base.get("saldo_sano", 0) or 0),
                "1_30": float(base.get("saldo_1_30", 0) or 0),
                "31_60": float(base.get("saldo_31_60", 0) or 0),
                "61_90": float(base.get("saldo_61_90", 0) or 0),
                "91_mas": float(base.get("saldo_mas_90", 0) or 0),
            }
            base["total"] = float(base.get("saldo_total", 0) or 0)
            base["num_facturas"] = int(base.get("num_facturas", 0) or 0)

            for r in grupo[1:]:
                base["total"] += float(r.get("saldo_total", 0) or 0)
                base["aging"]["por_vencer"] += float(r.get("saldo_sano", 0) or 0)
                base["aging"]["1_30"] += float(r.get("saldo_1_30", 0) or 0)
                base["aging"]["31_60"] += float(r.get("saldo_31_60", 0) or 0)
                base["aging"]["61_90"] += float(r.get("saldo_61_90", 0) or 0)
                base["aging"]["91_mas"] += float(r.get("saldo_mas_90", 0) or 0)
                base["num_facturas"] += int(r.get("num_facturas", 0) or 0)

            base["total_str"] = f"$ {base['total']:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
            consolidado.append(base)

        # --- Calcular resumen global ---
        total_global = sum(r["total"] for r in consolidado)
        facturas_vivas = sum(r["num_facturas"] for r in consolidado)

        total_1_30 = sum(r["aging"]["1_30"] for r in consolidado)
        total_31_60 = sum(r["aging"]["31_60"] for r in consolidado)
        total_61_90 = sum(r["aging"]["61_90"] for r in consolidado)
        total_91_mas = sum(r["aging"]["91_mas"] for r in consolidado)
        total_vencido = total_1_30 + total_31_60 + total_61_90 + total_91_mas
        pct_vencido = (total_vencido / total_global * 100) if total_global else 0
        total_por_vencer = total_global - total_vencido

        resumen_global = {
            "facturas_vivas": facturas_vivas,
            "total_global": f"$ {total_global:,.1f}".replace(",", "X").replace(".", ",").replace("X", "."),
            "total_por_vencer": f"$ {total_por_vencer:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."),
            "total_vencido": f"$ {total_vencido:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."),
            "pct_vencido": round(pct_vencido, 2),
            "total_1_30": f"$ {total_1_30:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."),
            "total_31_60": f"$ {total_31_60:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."),
            "total_61_90": f"$ {total_61_90:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."),
            "total_91_mas": f"$ {total_91_mas:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."),
        }

        # --- Detalle de facturas ---
        detalle = []
        if incluir_detalle:
            query_detalle = f"""
                SELECT
                    idfactura,
                    cliente_nombre,
                    centro_costo_nombre,
                    vendedor_nombre,
                    TO_CHAR(fecha, 'DD/MM/YYYY') AS fecha,
                    TO_CHAR(vencimiento, 'DD/MM/YYYY') AS vencimiento,
                    (CURRENT_DATE - vencimiento) AS dias_vencidos,
                    total,
                    pagos_total,
                    saldo,
                    public_url
                FROM facturas_enriquecidas
                WHERE {where_sql}
                ORDER BY cliente_nombre, fecha
            """
            result_detalle = db.session.execute(text(query_detalle), params).mappings().all()
            for r in result_detalle:
                r = dict(r)
                r["saldo_str"] = f"$ {r['saldo']:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
                r["total_str"] = f"$ {r['total']:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
                detalle.append(r)

        # --- Proyección por fecha ---
        query_proyeccion = f"""
            SELECT
                vencimiento::date AS fecha,
                SUM(saldo) AS total,
                (CASE WHEN vencimiento::date < CURRENT_DATE THEN true ELSE false END) AS vencido,
                json_agg(
                    json_build_object(
                        'idfactura', idfactura,
                        'cliente_nombre', cliente_nombre,
                        'saldo', saldo,
                        'public_url', public_url,
                        'dias_vencidos', (CURRENT_DATE - vencimiento)
                    )
                ) AS facturas
            FROM facturas_enriquecidas
            WHERE {where_sql}
            GROUP BY vencimiento::date
            ORDER BY fecha
        """
        result_proyeccion = db.session.execute(text(query_proyeccion), params).mappings().all()
        proyeccion_por_fecha = []
        for r in result_proyeccion:
            r = dict(r)
            r["fecha"] = r["fecha"].strftime("%d/%m/%Y")
            r["total_str"] = f"$ {r['total']:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
            proyeccion_por_fecha.append(r)

        return jsonify({
            "resumen_global": resumen_global,
            "consolidado": consolidado,
            "detalle": detalle if incluir_detalle else None,
            "proyeccion_por_fecha": proyeccion_por_fecha,
            "params": {
                "idcliente": idcliente,
                "desde": desde,
                "hasta": hasta,
                "detalle": incluir_detalle
            }
        })


    @app.route("/siigo/sync-pagos-egresos", methods=["POST"])
    @jwt_required()
    def siigo_sync_pagos_egresos():
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente asociado"}), 400

        deep = request.args.get("deep") in ("1","true","yes")
        batch = request.args.get("batch", default=None, type=int)
        only_missing = request.args.get("only_missing", default="1") in ("1","true","yes")
        since = request.args.get("since")  # opcional filtro por fecha

        try:
            mensaje = sync_pagos_egresos_desde_siigo(
                idcliente=idcliente,
                deep=deep,
                only_missing=only_missing,
                batch_size=batch,
                since=since
            )
            return jsonify({"mensaje": mensaje})
        except Exception as e:
            return jsonify({"error": str(e)}), 500


    @app.route("/siigo/debug-pago", methods=["GET"])
    @jwt_required()
    def siigo_debug_pago():
        """
        Devuelve detalle crudo de un recibo de egreso de Siigo y lo guardado en la BD (si existe).
        Uso:
        /siigo/debug-pago?idpago=12345
        Nota: requiere JWT. Superadmin puede pasar ?idcliente=.
        """
        claims = get_jwt()
        perfilid = claims.get("perfilid")
        idcliente = claims.get("idcliente")

        if perfilid == 0:
            idcliente = request.args.get("idcliente", type=int) or idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado o sin cliente en el token"}), 403

        idpago = request.args.get("idpago")
        if not idpago:
            return jsonify({"error": "Falta ?idpago="}), 400

        cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cred:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        token_data = _siigo_auth_json_for_client(cred)
        if token_data.get("_error"):
            return jsonify({"error": token_data["_error"]}), 502

        token = token_data.get("access_token")
        headers = _siigo_headers_bearer(token)
        base_url = cred.base_url.rstrip("/")
        tried_urls = []

        # intentar traer el JSON desde la API
        raw_data = None
        try:
            url = f"{base_url}/v1/payment-receipts/{idpago}"
            tried_urls.append(url)
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                raw_data = r.json()
            else:
                return jsonify({"error": f"HTTP {r.status_code}", "tried": tried_urls, "siigo_response": r.text}), 502
        except Exception as e:
            return jsonify({"error": str(e), "tried": tried_urls}), 502

        # buscar en la BD local
        pago = SiigoPagoProveedor.query.filter_by(idcliente=idcliente, idpago=idpago).first()
        pago_db = None
        if pago:
            pago_db = {
                "id": pago.id,
                "fecha": pago.fecha.isoformat() if pago.fecha else None,
                "proveedor_nombre": pago.proveedor_nombre,
                "metodo_pago": pago.metodo_pago,
                "valor": float(pago.valor or 0),
                "factura_aplicada": pago.factura_aplicada,
            }

        return jsonify({
            "idcliente": idcliente,
            "idpago": idpago,
            "tried": tried_urls,
            "siigo_raw": raw_data,
            "db_pago": pago_db
        })



    # Endpoint de depuración
    @app.route("/siigo/debug-cruce-pago", methods=["GET"])
    @jwt_required()
    def siigo_debug_cruce_pago():
        """
        Endpoint para depurar el cruce entre pagos y documentos soporte (idcompra).
        Uso: /siigo/debug-cruce-pago?idcompra=DS-1-1548
        Requiere autenticación JWT.
        """
        from models import SiigoCompra, SiigoPagoProveedor


        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente asociado"}), 403


        idcompra = request.args.get("idcompra")
        if not idcompra:
            return jsonify({"error": "Falta parámetro idcompra"}), 400


        compra = SiigoCompra.query.filter_by(idcliente=idcliente, idcompra=idcompra).first()
        if not compra:
            return jsonify({"error": f"Compra {idcompra} no encontrada"}), 404


        pagos = SiigoPagoProveedor.query.filter_by(idcliente=idcliente, factura_aplicada=idcompra).all()


        pagos_info = [
            {
                "idpago": p.idpago,
                "fecha": p.fecha.isoformat() if p.fecha else None,
                "valor": float(p.valor or 0),
                "metodo_pago": p.metodo_pago,
                "proveedor": p.proveedor_nombre
            } for p in pagos
        ]


        total_pagado = sum(float(p.valor or 0) for p in pagos)
        total_compra = float(compra.total or 0)
        saldo = round(total_compra - total_pagado, 2)


        return jsonify({
            "idcompra": idcompra,
            "total_compra": total_compra,
            "total_pagado": total_pagado,
            "saldo": saldo,
            "pagos": pagos_info,
            "estado": "PAGADO" if saldo <= 0 else ("PARCIAL" if total_pagado > 0 else "PENDIENTE")
        })




    # Permite actualizar pagos y estados de facturas/documentos soporte
    @app.route("/siigo/actualizar-estado-pagos", methods=["POST"])
    @jwt_required()
    def actualizar_estado_pagos():
        """
        Recalcula el estado de pago de cada factura/documento soporte
        cruzando con los pagos cargados desde Siigo.
        Guarda el estado ("SI", "NO", "PARCIAL") en cada línea de siigo_pagos_proveedores.
        """
        from models import SiigoPagoProveedor, SiigoCompra
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente asociado"}), 403

        # 1. Obtener compras del cliente con sus totales (clave: factura_proveedor + proveedor_identificacion)
        compras = SiigoCompra.query.filter_by(idcliente=idcliente).all()
        compras_dict = {}
        for c in compras:
            clave = (c.factura_proveedor, c.proveedor_identificacion)
            compras_dict[clave] = float(c.total or 0)

        print(f"📦 Compras cargadas en memoria: {len(compras_dict)}")

        # 2. Obtener todos los pagos del cliente
        pagos = SiigoPagoProveedor.query.filter_by(idcliente=idcliente).all()
        pagos_por_factura = {}

        # 3. Agrupar pagos por (factura_aplicada, proveedor_identificacion)
        for pago in pagos:
            if not pago.factura_aplicada or not pago.proveedor_identificacion:
                print(f"⚠️ Pago sin factura/proveedor -> idpago={pago.idpago}")
                continue
            clave = (pago.factura_aplicada, pago.proveedor_identificacion)
            pagos_por_factura.setdefault(clave, []).append(pago)

        print(f"💰 Pagos agrupados por factura: {len(pagos_por_factura)}")

        # 4. Calcular estado para cada grupo de pagos de una factura
        for clave, pagos_factura in pagos_por_factura.items():
            factura, prov_id = clave
            total_pagado = round(sum(float(p.valor or 0) for p in pagos_factura), 2)
            total_factura = compras_dict.get(clave, 0)

            if total_factura == 0:
                estado = "NO"
            elif total_pagado >= total_factura:
                estado = "SI"
            elif total_pagado > 0:
                estado = "PARCIAL"
            else:
                estado = "NO"

            print(f"🔎 Cruce factura={factura}, proveedor={prov_id} -> total_factura={total_factura}, total_pagado={total_pagado}, estado={estado}")

            # 5. Guardar el estado en todos los pagos vinculados a esa factura
            for pago in pagos_factura:
                pago.factura_pagada = estado

        db.session.commit()

        print("✅ Cruce finalizado y estados actualizados")

        # 6. Resumen de estados
        resumen = {
            "SI": SiigoPagoProveedor.query.filter_by(idcliente=idcliente, factura_pagada="SI").count(),
            "NO": SiigoPagoProveedor.query.filter_by(idcliente=idcliente, factura_pagada="NO").count(),
            "PARCIAL": SiigoPagoProveedor.query.filter_by(idcliente=idcliente, factura_pagada="PARCIAL").count(),
            "NULL": SiigoPagoProveedor.query.filter_by(idcliente=idcliente, factura_pagada=None).count(),
        }

        return jsonify({
            "status": "ok",
            "msg": "Estados de pago actualizados correctamente",
            "facturas_actualizadas": len(pagos_por_factura),
            "pagos_actualizados": len(pagos),
            "resumen_estados": resumen
        })





    @app.route("/siigo/sync-compras", methods=["POST"])
    def siigo_sync_compras():
        idcliente = obtener_idcliente_desde_request()
        if not idcliente:
            return jsonify({"error": "Cliente no autorizado"}), 403

        deep = request.args.get("deep") in ("1", "true", "yes")
        batch = request.args.get("batch", default=None, type=int)
        only_missing = request.args.get("only_missing", default="1") in ("1", "true", "yes")
        since = request.args.get("since")
        modo_sync_all = request.headers.get("X-SYNC-ALL") == "1"

        try:
            if modo_sync_all:
                # 🔹 Ejecutar directamente (sin hilo)
                resultado = sync_compras_desde_siigo(
                    idcliente=idcliente,
                    deep=deep,
                    batch_size=batch if batch else 50,
                    only_missing=only_missing,
                    since=since,
                )
                return jsonify({"mensaje": f"Compras sincronizadas: {resultado}"}), 200

            # 🔹 Modo UI manual: background thread
            def run_background():
                with app.app_context():
                    try:
                        print(f"[sync-compras] 🔁 Iniciando para cliente {idcliente}")
                        sync_compras_desde_siigo(
                            idcliente=idcliente,
                            deep=deep,
                            batch_size=batch if batch else 50,
                            only_missing=only_missing,
                            since=since,
                        )
                        print(f"[sync-compras] ✅ Finalizado para cliente {idcliente}")
                    except Exception as e:
                        print(f"[sync-compras] ❌ Error en background: {e}")

            threading.Thread(target=run_background, daemon=True).start()
            return jsonify({"mensaje": "Sincronización de compras iniciada en segundo plano."}), 202
        except Exception as e:
            return jsonify({"error": str(e)}), 500




    @app.route("/siigo/debug-compra", methods=["GET"])
    @jwt_required()
    def siigo_debug_compra():
        from models import SiigoCompra, SiigoCompraItem

        claims = get_jwt()
        perfilid = claims.get("perfilid")
        idcliente = claims.get("idcliente")

        # superadmin puede ver otro cliente
        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0 and q_idcliente:
            idcliente = q_idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado o sin cliente en el token"}), 403

        compra_id = request.args.get("idcompra")
        uuid = request.args.get("uuid")

        if not compra_id and not uuid:
            return jsonify({"error": "Proporciona ?idcompra= o ?uuid="}), 400

        # obtener credenciales y autenticar
        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg:
            return jsonify({"error": "Credenciales de Siigo no configuradas"}), 400

        auth_data = _siigo_auth_json_for_client(cfg)
        if auth_data.get("_error"):
            return jsonify({"error": auth_data["_error"]}), 502

        token = auth_data.get("access_token")
        if not token:
            return jsonify({"error": "No se obtuvo token de Siigo"}), 502

        base_url = cfg.base_url.rstrip("/")
        headers = _siigo_headers_bearer(token)

        tried = []
        raw_detail = None

        try:
            if uuid:
                url = f"{base_url}/v1/support-documents/{uuid}"
                tried.append(url)
                r = requests.get(url, headers=headers, timeout=60)
                if r.status_code == 200:
                    raw_detail = r.json()
            elif compra_id:
                url = f"{base_url}/v1/support-documents?document={compra_id}"
                tried.append(url)
                r = requests.get(url, headers=headers, timeout=60)
                if r.status_code == 200:
                    results = r.json().get("results")
                    if results:
                        raw_detail = results[0]
        except Exception as e:
            return jsonify({"error": str(e), "tried": tried}), 502

        # buscar en la base de datos local
        compra_db = SiigoCompra.query.filter_by(idcliente=idcliente, idcompra=compra_id).first()
        items_db = []
        if compra_db:
            items_db = SiigoCompraItem.query.filter_by(compra_id=compra_db.id).all()

        def _dec(v):
            from decimal import Decimal
            if isinstance(v, Decimal): return float(v)
            if isinstance(v, datetime): return v.isoformat()
            return v

        def compra_to_dict(c):
            if not c: return None
            return {
                "id": c.id,
                "idcliente": c.idcliente,
                "idcompra": c.idcompra,
                "fecha": c.fecha.isoformat() if c.fecha else None,
                "vencimiento": c.vencimiento.isoformat() if c.vencimiento else None,
                "proveedor_nombre": c.proveedor_nombre,
                "estado": c.estado,
                "total": _dec(c.total),
                "saldo": _dec(c.saldo),
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }

        def item_to_dict(i):
            return {
                "id": i.id,
                "compra_id": i.compra_id,
                "descripcion": i.descripcion,
                "cantidad": _dec(i.cantidad),
                "precio": _dec(i.precio),
                "impuestos": _dec(i.impuestos),
            }

        return jsonify({
            "query_params": {"uuid": uuid, "idcompra": compra_id, "idcliente": idcliente},
            "siigo_tried_urls": tried,
            "siigo_raw_detail": raw_detail,
            "db_compra": compra_to_dict(compra_db),
            "db_items": [item_to_dict(x) for x in items_db]
        })




    @app.route("/siigo/debug-purchases-raw", methods=["GET"])
    def siigo_debug_purchases_raw():
        # NO jwt_required, para pruebas
        # Aquí puedes pasar idcliente por query param si quieres
        idcliente = request.args.get("idcliente", type=int)
        if not idcliente:
            return jsonify({"error": "Falta idcliente (ej: /siigo/debug-purchases-raw?idcliente=1)"}), 400

        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        auth_data = _siigo_auth_json_for_client(cfg)
        if not isinstance(auth_data, dict):
            return jsonify({"error": "Auth inesperado", "detalle": str(auth_data)}), 500

        token = auth_data.get("access_token")
        if not token:
            return jsonify({"error": "No se obtuvo access_token", "detalle": auth_data}), 500

        base_url = cfg.base_url.rstrip("/")
        headers = _siigo_headers_bearer(token)

        url = f"{base_url}/v1/purchases?page_size=20"  # número pequeño para ver ejemplo
        try:
            r = requests.get(url, headers=headers, timeout=60)
        except Exception as e:
            return jsonify({"error": "Error al hacer la petición HTTP", "detalle": str(e)}), 500

        status = r.status_code
        # Intenta parsear JSON, si no, devuelve texto
        try:
            body = r.json()
        except Exception:
            body = r.text

        return jsonify({
            "status": status,
            "url": url,
            "body": body
        }), status

    # Consultar detalle de un Recibo de Pago en la api de Siigo para ver detalle de lo que entrega - raw
    # se consulta asi: http://localhost:5000/siigo/debug-pago-raw?idcliente=1&idpago=713   (RP-1-713)
    @app.route("/siigo/debug-todos-pagos-raw", methods=["GET"])
    def siigo_debug_todos_pagos_raw():
        idcliente = request.args.get("idcliente", type=int)
        if not idcliente:
            return jsonify({"error": "Falta idcliente"}), 400

        cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cred:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        token_data = _siigo_auth_json_for_client(cred)
        token = token_data.get("access_token")
        headers = _siigo_headers_bearer(token)
        base_url = cred.base_url.rstrip("/")

        # recorrer muchas páginas
        all_pagos = []
        page = 1
        page_size = 100
        while True:
            url = f"{base_url}/v1/payment-receipts?page={page}&page_size={page_size}"
            r = requests.get(url, headers=headers, timeout=60)
            if r.status_code != 200:
                break
            data = r.json()
            resultados = data.get("results") or []
            all_pagos.extend(resultados)
            if len(resultados) < page_size:
                break
            page += 1

        return jsonify({"pagos": all_pagos})




    # Buscar el ID real (UUID) del recibo de pago por nombre (ej: RP-1-713)
    @app.route("/siigo/debug-buscar-pago", methods=["GET"])
    def siigo_debug_buscar_pago():
        """
        Busca el ID real (UUID) del recibo de pago por nombre (ej: RP-1-713)
        Uso: /siigo/debug-buscar-pago?idcliente=1&nombre_pago=RP-1-713
        """
        idcliente = request.args.get("idcliente", type=int)
        nombre_pago = request.args.get("nombre_pago")

        if not idcliente or not nombre_pago:
            return jsonify({
                "error": "Faltan parámetros. Uso: /siigo/debug-buscar-pago?idcliente=1&nombre_pago=RP-1-713"
            }), 400

        cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cred:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        # Autenticación
        token_data = _siigo_auth_json_for_client(cred)
        if token_data.get("_error"):
            return jsonify({"error": token_data["_error"]}), 502

        token = token_data.get("access_token")
        headers = _siigo_headers_bearer(token)
        base_url = cred.base_url.rstrip("/")
        url = f"{base_url}/v1/payment-receipts?page_size=100"

        try:
            r = requests.get(url, headers=headers, timeout=60)
        except Exception as e:
            return jsonify({"error": "Error HTTP", "detalle": str(e)}), 500

        try:
            pagos = r.json().get("results", [])
        except Exception:
            return jsonify({"error": "Respuesta no es JSON", "detalle": r.text}), 500

        encontrados = []
        for pago in pagos:
            doc = pago.get("document", {})
            if doc.get("name") == nombre_pago:
                encontrados.append({
                    "uuid": pago.get("id"),
                    "documento": doc,
                    "total": pago.get("total"),
                    "fecha": pago.get("date"),
                    "proveedor": pago.get("provider", {}).get("name")
                })

        return jsonify({
            "busqueda": nombre_pago,
            "coincidencias": encontrados
        })





    @app.route("/siigo/debug-documentos-soporte-tipo", methods=["GET"])
    def siigo_debug_documentos_soporte_tipo():
        idcliente = request.args.get("idcliente", type=int)
        if not idcliente:
            return jsonify({"error": "Falta idcliente (ej: /siigo/debug-documentos-soporte-tipo?idcliente=1)"}), 400

        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        auth_data = _siigo_auth_json_for_client(cfg)
        if not isinstance(auth_data, dict):
            return jsonify({"error": "Auth inesperado", "detalle": str(auth_data)}), 500

        token = auth_data.get("access_token")
        if not token:
            return jsonify({"error": "No se obtuvo access_token", "detalle": auth_data}), 500

        base_url = cfg.base_url.rstrip("/")
        headers = _siigo_headers_bearer(token)

        # 1. Obtener tipos de documento de compra
        doc_types_url = f"{base_url}/v1/document-types?type=FC"
        try:
            r_doc = requests.get(doc_types_url, headers=headers, timeout=60)
            doc_types = r_doc.json()
        except Exception as e:
            return jsonify({"error": "Error al consultar tipos de documento", "detalle": str(e)}), 500

        # 2. Filtrar solo los tipos que son documento soporte
        soporte_ids = [
            d["id"] for d in doc_types if d.get("document_support") is True
        ]

        # 3. Consultar /purchases
        purchases_url = f"{base_url}/v1/purchases?page_size=50"
        try:
            r = requests.get(purchases_url, headers=headers, timeout=60)
            compras_data = r.json()
        except Exception as e:
            return jsonify({"error": "Error al consultar compras", "detalle": str(e)}), 500

        # 4. Filtrar solo los que tienen document.id en soporte_ids
        resultados = compras_data.get("results", [])
        docs_soporte = [
            compra for compra in resultados
            if compra.get("document", {}).get("id") in soporte_ids
        ]

        return jsonify({
            "status": r.status_code,
            "document_support_ids": soporte_ids,
            "total_documentos_soporte": len(docs_soporte),
            "documentos_soporte": docs_soporte
        })


    @app.route("/siigo/debug-compras-json-completo", methods=["GET"])
    def siigo_debug_compras_json_completo():
        idcliente = request.args.get("idcliente", type=int)
        if not idcliente:
            return jsonify({"error": "Falta idcliente"}), 400

        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        auth_data = _siigo_auth_json_for_client(cfg)
        if not isinstance(auth_data, dict):
            return jsonify({"error": "Auth inesperado", "detalle": str(auth_data)}), 500

        token = auth_data.get("access_token")
        if not token:
            return jsonify({"error": "No se obtuvo access_token", "detalle": auth_data}), 500

        base_url = cfg.base_url.rstrip("/")
        headers = _siigo_headers_bearer(token)

        url = f"{base_url}/v1/purchases?page_size=300"
        try:
            r = requests.get(url, headers=headers, timeout=60)
            return jsonify({
                "status": r.status_code,
                "url": url,
                "body": r.json()
            }), r.status_code
        except Exception as e:
            return jsonify({"error": "Fallo en la consulta", "detalle": str(e)}), 500




    @app.route("/siigo/debug-proveedores-raw", methods=["GET"])
    def siigo_debug_proveedores_raw():
        idcliente = request.args.get("idcliente", type=int)
        if not idcliente:
            return jsonify({"error": "Falta idcliente (ej: /siigo/debug-proveedores-raw?idcliente=1)"}), 400

        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        auth_data = _siigo_auth_json_for_client(cfg)
        if not isinstance(auth_data, dict):
            return jsonify({"error": "Auth inesperado", "detalle": str(auth_data)}), 500

        token = auth_data.get("access_token")
        if not token:
            return jsonify({"error": "No se obtuvo access_token", "detalle": auth_data}), 500

        base_url = cfg.base_url.rstrip("/")
        headers = _siigo_headers_bearer(token)

        posibles_rutas = [
            "contacts",
        ]

        resultados = []
        for ruta in posibles_rutas:
            url = f"{base_url}/v1/{ruta}?page_size=20"
            try:
                r = requests.get(url, headers=headers, timeout=60)
            except Exception as e:
                resultados.append({
                    "ruta": ruta,
                    "status": "error",
                    "error": str(e),
                })
                continue

            status = r.status_code
            body = None
            try:
                body = r.json()
            except Exception:
                body = r.text

            resultados.append({
                "ruta": ruta,
                "status": status,
                "body": body,
            })

            if status == 200:
                # encontramos una ruta funcional, la devolvemos ya
                return jsonify({
                    "ruta_valida": ruta,
                    "url": url,
                    "status": status,
                    "body": body
                }), 200

        # Si ninguna funcionó, devolvemos todos los intentos para debugging
        return jsonify({
            "error": "No se encontró ruta válida para proveedores",
            "intentos": resultados
        }), 404


    # Endpoint consulta y prueba extracion proveedores en el Navegador (probar asi:  http://localhost:5000/siigo/debug-proveedores?idcliente=1)
    @app.route("/siigo/debug-proveedores", methods=["GET"])
    def siigo_debug_proveedores2():
        from datetime import datetime

        idcliente = request.args.get("idcliente", type=int)
        if not idcliente:
            return jsonify({"error": "Falta idcliente (ej: /siigo/debug-proveedores?idcliente=1)"}), 400

        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        auth_data = _siigo_auth_json_for_client(cfg)
        if not isinstance(auth_data, dict):
            return jsonify({"error": "Auth inesperado", "detalle": str(auth_data)}), 500

        token = auth_data.get("access_token")
        if not token:
            return jsonify({"error": "No se obtuvo access_token", "detalle": auth_data}), 500

        base_url = cfg.base_url.rstrip("/")
        headers = _siigo_headers_bearer(token)

        page = 1
        page_size = 100
        proveedores = []

        while True:
            url = f"{base_url}/v1/customers?page={page}&page_size={page_size}"
            try:
                r = requests.get(url, headers=headers, timeout=60)
            except Exception as e:
                return jsonify({"error": f"Error al conectar con Siigo: {str(e)}"}), 500

            if r.status_code != 200:
                return jsonify({
                    "error": "Error en respuesta de Siigo",
                    "status": r.status_code,
                    "body": r.text,
                    "url": url
                }), 500

            data = r.json()
            if not isinstance(data, list):
                data = data.get("results", [])

            solo_proveedores = [c for c in data if c.get("type") == "Supplier"]
            proveedores.extend(solo_proveedores)

            # ¿hay más páginas?
            if isinstance(r.json(), dict):
                links = r.json().get("_links", {})
                if not links.get("next") or not links["next"].get("href"):
                    break
            else:
                # No paginación si es lista directa
                break

            page += 1

        return jsonify({
            "total_proveedores": len(proveedores),
            "proveedores": proveedores[:20],  # solo los primeros 20 para visualización
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }), 200



    # realiza la sincronización de provedores trayendo tanprovedores, clientes y otros (ULTIMO SEP 24 2025)
    @app.route("/siigo/sync-proveedores", methods=["POST"])
    
    def siigo_sync_proveedores():
        idcliente = obtener_idcliente_desde_request()
        if not idcliente:
            return jsonify({"error": "Cliente no autorizado"}), 403


        cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cred:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        access_key = dec(cred.client_secret)
        if not access_key:
            return jsonify({"error": "No se pudo desencriptar access_key"}), 400

        try:
            token_data = siigo_auth_json(cred.base_url, cred.client_id, access_key)
            token = token_data["access_token"]
            headers = _headers_bearer(token)

            base_url = cred.base_url.rstrip("/")
            page = 1
            page_size = 100
            total_insertados = 0
            total_actualizados = 0

            while True:
                url = f"{base_url}/v1/customers?page={page}&page_size={page_size}"
                r = requests.get(url, headers=headers)
                if r.status_code != 200:
                    break

                payload = r.json()
                results = payload if isinstance(payload, list) else payload.get("results", [])
                if not results:
                    break

                for c in results:
                    # Si no tiene identificación, ignorar
                    identificacion = c.get("identification")
                    if not identificacion:
                        continue

                    nombre_raw = c.get("name", [])
                    nombre = " ".join([n for n in nombre_raw if n is not None]).strip()
                    tipo_ident = quitar_tildes(c.get("id_type", {}).get("name", ""))
                    dv = c.get("check_digit", "")
                    direccion = c.get("address", {}).get("address", "")
                    ciudad = quitar_tildes(c.get("address", {}).get("city", {}).get("city_name", ""))
                    telefonos = c.get("phones", [])
                    telefono = ""
                    if telefonos:
                        tel = telefonos[0]
                        telefono = f"{tel.get('indicative', '')} {tel.get('number', '')}".strip()
                    estado = "Activo" if c.get("active") else "Inactivo"

                    stmt = insert(SiigoProveedor).values(
                        idcliente=idcliente,
                        nombre=nombre,
                        tipo_identificacion=tipo_ident,
                        identificacion=identificacion,
                        digito_verificacion=dv,
                        direccion=direccion,
                        ciudad=ciudad,
                        telefono=telefono,
                        estado=estado
                    ).on_conflict_do_update(
                        index_elements=["idcliente", "identificacion"],
                        set_={
                            "nombre": nombre,
                            "tipo_identificacion": tipo_ident,
                            "digito_verificacion": dv,
                            "direccion": direccion,
                            "ciudad": ciudad,
                            "telefono": telefono,
                            "estado": estado
                        }
                    )

                    res = db.session.execute(stmt)
                    if res.rowcount == 1:
                        total_insertados += 1
                    else:
                        total_actualizados += 1

                if "_links" in payload and payload["_links"].get("next"):
                    page += 1
                else:
                    break

            db.session.commit()
            return jsonify({
                "mensaje": f"Proveedores sincronizados: {total_insertados}, actualizados: {total_actualizados}"
            }), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500



    # PReview en pagina de los proveedores que se cargaran
    @app.route("/siigo/preview-proveedores", methods=["GET"])
    def siigo_preview_proveedores():
        idcliente = request.args.get("idcliente", type=int)
        if not idcliente:
            return jsonify({"error": "Falta idcliente (ej: /siigo/preview-proveedores?idcliente=1)"}), 400

        cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cred:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        access_key = dec(cred.client_secret)
        if not access_key:
            return jsonify({"error": "No se pudo desencriptar access_key"}), 400

        try:
            token_data = siigo_auth_json(cred.base_url, cred.client_id, access_key)
            token = token_data["access_token"]
            headers = _headers_bearer(token)

            base_url = cred.base_url.rstrip("/")
            page = 1
            page_size = 100
            proveedores = []

            while True:
                url = f"{base_url}/v1/customers?page={page}&page_size={page_size}"
                r = requests.get(url, headers=headers)
                if r.status_code != 200:
                    break

                payload = r.json()
                results = payload if isinstance(payload, list) else payload.get("results", [])
                if not results:
                    break

                for c in results:
                    if c.get("type") != "Supplier":
                        continue

                    nombre = " ".join(c.get("name", [])).strip()
                    tipo_ident = quitar_tildes(c.get("id_type", {}).get("name", ""))
                    identificacion = c.get("identification", "")
                    dv = c.get("check_digit", "")
                    direccion = c.get("address", {}).get("address", "")
                    ciudad = quitar_tildes(c.get("address", {}).get("city", {}).get("city_name", ""))
                    telefonos = c.get("phones", [])
                    telefono = ""
                    if telefonos:
                        tel = telefonos[0]
                        telefono = f"{tel.get('indicative', '')} {tel.get('number', '')}".strip()

                    estado = "Activo" if c.get("active") else "Inactivo"

                    proveedor = {
                        "nombre": nombre,
                        "tipo_identificacion": tipo_ident,
                        "identificacion": identificacion,
                        "digito_verificacion": dv,
                        "direccion": direccion,
                        "ciudad": ciudad,
                        "telefono": telefono,
                        "estado": estado
                    }

                    proveedores.append(proveedor)

                if "_links" in payload and payload["_links"].get("next"):
                    page += 1
                else:
                    break

            return jsonify({
                "proveedores": proveedores,
                "total": len(proveedores)
            }), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500



    @app.route("/siigo/cargar-proveedores", methods=["POST"])
    @jwt_required()
    def cargar_proveedores_excel():
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente asociado"}), 400

        if "archivo" not in request.files:
            return jsonify({"error": "Archivo no proporcionado"}), 400

        file = request.files["archivo"]

        try:
            # Usa la fila 6 como encabezado
            df = pd.read_excel(file, header=6)
        except Exception as e:
            return jsonify({"error": f"No se pudo leer el Excel: {str(e)}"}), 400

        requeridos = [
            "Nombre tercero", "Tipo de identificación", "Identificación",
            "Digito verificación", "Dirección", "Ciudad", "Teléfono.", "Estado"
        ]
        faltantes = [col for col in requeridos if col not in df.columns]
        if faltantes:
            return jsonify({"error": f"Faltan columnas requeridas en el archivo: {', '.join(faltantes)}"}), 400

        nuevos = 0
        actualizados = 0
        for _, row in df.iterrows():
            identificacion = str(row["Identificación"]).strip()
            proveedor = SiigoProveedor.query.filter_by(idcliente=idcliente, identificacion=identificacion).first()

            datos = dict(
                nombre=str(row["Nombre tercero"]).strip(),
                tipo_identificacion=str(row["Tipo de identificación"]).strip(),
                digito_verificacion=str(row.get("Digito verificación", "")).strip(),
                direccion=str(row.get("Dirección", "")).strip(),
                ciudad=str(row.get("Ciudad", "")).strip(),
                telefono=str(row.get("Teléfono.", "")).strip(),
                estado=str(row.get("Estado", "")).strip(),
            )

            if proveedor:
                for k, v in datos.items():
                    setattr(proveedor, k, v)
                actualizados += 1
            else:
                db.session.add(SiigoProveedor(idcliente=idcliente, identificacion=identificacion, **datos))
                nuevos += 1

        db.session.commit()
        return jsonify({"mensaje": f"Proveedores cargados correctamente. Nuevos: {nuevos}, Actualizados: {actualizados}"})



    #Reporte de Compras a Proveedores
    # --- ENDPOINT: Reporte General de Compras por Proveedor ---
    @app.route("/reportes/compras/proveedores", methods=["GET"])
    @jwt_required()
    def reporte_compras_proveedores():
        from sqlalchemy.sql import text
        from datetime import datetime

        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente"}), 403

        incluir_detalle = request.args.get("detalle", "0") == "1"
        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        estado = request.args.get("estado")  # "pagado" | "pendiente"

        condiciones = ["idcliente = :idcliente"]
        params = {"idcliente": idcliente}

        def validar_fecha(fecha_str):
            try:
                return datetime.strptime(fecha_str, "%Y-%m-%d").date()
            except Exception:
                return None

        if desde and validar_fecha(desde):
            condiciones.append("fecha >= :desde")
            params["desde"] = desde
        if hasta and validar_fecha(hasta):
            condiciones.append("fecha <= :hasta")
            params["hasta"] = hasta

        # --- Filtro por estado real de siigo_compras ---
        if estado:
            estado_norm = estado.strip().lower()
            if estado_norm in ["pagado", "pendiente"]:
                condiciones.append("LOWER(estado) = :estado")
                params["estado"] = estado_norm

        where_sql = " AND ".join(condiciones)

        # --- Resumen por proveedor ---
        query = f"""
            SELECT
                COALESCE(proveedor_identificacion, '') AS proveedor_identificacion,
                COALESCE(proveedor_nombre, '') AS proveedor_nombre,
                COUNT(*) AS num_compras,
                SUM(COALESCE(total, 0)) AS total_compras,
                SUM(CASE WHEN estado = 'pendiente' THEN saldo ELSE 0 END) AS total_saldo,
                MAX(fecha) AS ultima_fecha
            FROM siigo_compras
            WHERE {where_sql}
            GROUP BY proveedor_identificacion, proveedor_nombre
            HAVING SUM(COALESCE(total, 0)) > 0
            ORDER BY total_compras DESC
        """
        rows = db.session.execute(text(query), params).mappings().all()
        resultado = [dict(r) for r in rows]

        for r in resultado:
            r["total_pagado"] = float(r["total_compras"] or 0) - float(r["total_saldo"] or 0)

        detalle = []
        if incluir_detalle:
            query_detalle = f"""
                SELECT
                    idcompra,
                    factura_proveedor,
                    proveedor_identificacion,
                    proveedor_nombre,
                    fecha,
                    vencimiento,
                    total,
                    saldo,
                    estado
                FROM siigo_compras
                WHERE {where_sql}
                ORDER BY proveedor_nombre, fecha DESC
            """
            rows_detalle = db.session.execute(text(query_detalle), params).mappings().all()
            detalle = [dict(r) for r in rows_detalle]

        return jsonify({
            "resumen": resultado,
            "detalle": detalle if incluir_detalle else None
        })




    # --- ENDPOINT: Reporte de Ítems de Compra ---
    @app.route("/reportes/compras/items", methods=["GET"])
    @jwt_required()
    def reporte_compras_items():
        from sqlalchemy.sql import text

        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente"}), 403

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        proveedor = request.args.get("proveedor")
        codigo = request.args.get("codigo")

        condiciones = ["sc.idcliente = :idcliente"]
        params = {"idcliente": idcliente}

        if desde:
            condiciones.append("sc.fecha >= :desde")
            params["desde"] = desde
        if hasta:
            condiciones.append("sc.fecha <= :hasta")
            params["hasta"] = hasta
        if proveedor:
            condiciones.append("sc.proveedor_identificacion = :proveedor")
            params["proveedor"] = proveedor
        if codigo:
            condiciones.append("sci.codigo = :codigo")
            params["codigo"] = codigo

        where_sql = " AND ".join(condiciones)

        query = f"""
            SELECT
                sci.descripcion,
                sci.codigo,
                SUM(sci.cantidad) AS total_cantidad,
                SUM(sci.precio * sci.cantidad) AS total_gastado,
                CASE WHEN SUM(sci.cantidad) > 0 THEN
                    SUM(sci.precio * sci.cantidad) / SUM(sci.cantidad)
                ELSE 0 END AS precio_promedio
            FROM siigo_compras_items sci
            JOIN siigo_compras sc ON sci.compra_id = sc.id
            WHERE {where_sql}
            GROUP BY sci.descripcion, sci.codigo
            ORDER BY total_gastado DESC
        """

        rows = db.session.execute(text(query), params).mappings().all()
        resultado = [dict(r) for r in rows]

        return jsonify({"items": resultado})



    # --- ENDPOINT: Reporte Financiero Compras y Gastos ---
    # --- ENDPOINT 1: Reporte Financiero Compras y Gastos (KPIs + Evolución Mensual) ---
    @app.route("/reportes/financiero/compras-gastos", methods=["GET"])
    @jwt_required()
    def reporte_financiero_compras_gastos():
        from sqlalchemy.sql import text
        from datetime import datetime

        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente"}), 403

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        centro_costos = request.args.get("centro_costos")

        def validar_fecha(fecha_str):
            try:
                return datetime.strptime(fecha_str, "%Y-%m-%d").date()
            except Exception:
                return None

        desde_valida = validar_fecha(desde) if desde else None
        hasta_valida = validar_fecha(hasta) if hasta else None

        condiciones = ["c.idcliente = :idcliente"]
        params = {"idcliente": idcliente}

        if desde_valida:
            condiciones.append("c.fecha >= :desde")
            params["desde"] = desde_valida
        if hasta_valida:
            condiciones.append("c.fecha <= :hasta")
            params["hasta"] = hasta_valida
        if centro_costos:
            condiciones.append("c.cost_center = :centro_costos")
            params["centro_costos"] = centro_costos

        where_sql = " AND ".join(condiciones)

        # --- Evolución mensual ---
        query_evolucion = f"""
            SELECT
                date_trunc('month', c.fecha) AS mes,
                SUM(c.total) AS total_compras,
                SUM(CASE WHEN c.estado = 'pagado' THEN c.total ELSE 0 END) AS total_pagadas,
                SUM(CASE WHEN c.estado = 'pendiente' THEN c.saldo ELSE 0 END) AS total_pendientes
            FROM siigo_compras c
            WHERE {where_sql}
            GROUP BY mes
            ORDER BY mes
        """
        rows_evol = db.session.execute(text(query_evolucion), params).mappings().all()

        # --- KPIs generales ---
        query_kpis = f"""
            SELECT
                COUNT(*) AS total_facturas,
                SUM(c.total) AS total_compras,
                SUM(CASE WHEN c.estado = 'pagado' THEN c.total ELSE 0 END) AS total_pagado,
                SUM(CASE WHEN c.estado = 'pendiente' THEN c.saldo ELSE 0 END) AS total_saldo,
                SUM(CASE WHEN c.estado = 'pagado' THEN 1 ELSE 0 END) AS facturas_pagadas,
                SUM(CASE WHEN c.estado = 'pendiente' THEN 1 ELSE 0 END) AS facturas_pendientes,

                -- 👇 nuevos KPIs
                SUM(CASE WHEN c.idcompra LIKE 'FC-%' THEN 1 ELSE 0 END) AS compras_x_factura,
                SUM(CASE WHEN c.idcompra LIKE 'FC-%' THEN c.total ELSE 0 END) AS valor_compras_x_factura,
                SUM(CASE WHEN c.idcompra LIKE 'DS-%' THEN 1 ELSE 0 END) AS compras_x_cta_cobro,
                SUM(CASE WHEN c.idcompra LIKE 'DS-%' THEN c.total ELSE 0 END) AS valor_compras_x_cta_cobro
            FROM siigo_compras c
            WHERE {where_sql}
        """
        row_kpis = db.session.execute(text(query_kpis), params).mappings().first()

        return jsonify({
            "kpis": dict(row_kpis),
            "evolucion": [dict(r) for r in rows_evol]
        })


    # --- ENDPOINT 2: Top 15 Proveedores por valor de compras ---
    @app.route("/reportes/financiero/compras-gastos/top-proveedores", methods=["GET"])
    @jwt_required()
    def top_proveedores_compras():
        from sqlalchemy.sql import text
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        centro_costos = request.args.get("centro_costos")

        condiciones = ["c.idcliente = :idcliente"]
        params = {"idcliente": idcliente}

        if desde:
            condiciones.append("c.fecha >= :desde")
            params["desde"] = desde
        if hasta:
            condiciones.append("c.fecha <= :hasta")
            params["hasta"] = hasta
        if centro_costos:
            condiciones.append("c.cost_center = :centro_costos")
            params["centro_costos"] = centro_costos

        where_sql = " AND ".join(condiciones)

        sql = text(f"""
            SELECT
                c.proveedor_nombre,
                COUNT(*) AS num_facturas,
                SUM(c.total) AS total_compras
            FROM siigo_compras c
            WHERE {where_sql}
            GROUP BY c.proveedor_nombre
            ORDER BY total_compras DESC
            LIMIT 15
        """)
        rows = [dict(r) for r in db.session.execute(sql, params).mappings().all()]
        return jsonify(rows)


    # --- ENDPOINT 3: Top 15 Proveedores por número de facturas ---
    @app.route("/reportes/financiero/compras-gastos/top-proveedores-facturas", methods=["GET"])
    @jwt_required()
    def top_proveedores_facturas():
        from sqlalchemy.sql import text
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        centro_costos = request.args.get("centro_costos")

        condiciones = ["c.idcliente = :idcliente"]
        params = {"idcliente": idcliente}

        if desde:
            condiciones.append("c.fecha >= :desde")
            params["desde"] = desde
        if hasta:
            condiciones.append("c.fecha <= :hasta")
            params["hasta"] = hasta
        if centro_costos:
            condiciones.append("c.cost_center = :centro_costos")
            params["centro_costos"] = centro_costos

        where_sql = " AND ".join(condiciones)

        sql = text(f"""
            SELECT
                c.proveedor_nombre,
                COUNT(*) AS num_facturas
            FROM siigo_compras c
            WHERE {where_sql}
            GROUP BY c.proveedor_nombre
            ORDER BY num_facturas DESC
            LIMIT 15
        """)
        rows = [dict(r) for r in db.session.execute(sql, params).mappings().all()]
        return jsonify(rows)


    # --- ENDPOINT 4: Detalle de facturas por mes ---
    @app.route("/reportes/financiero/compras-gastos/detalle", methods=["GET"])
    @jwt_required()
    def detalle_facturas_mes():
        from sqlalchemy.sql import text
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        mes = request.args.get("mes")
        estado = request.args.get("estado")  # "total" | "pagado" | "pendiente"
        centro_costos = request.args.get("centro_costos")

        if not mes:
            return jsonify({"error": "Mes requerido"}), 400

        condiciones = ["c.idcliente = :idcliente", "TO_CHAR(c.fecha, 'YYYY-MM') = :mes"]
        params = {"idcliente": idcliente, "mes": mes}

        if estado in ("pagado", "pendiente"):
            condiciones.append("c.estado = :estado")
            params["estado"] = estado

        if centro_costos:
            condiciones.append("c.cost_center = :centro_costos")
            params["centro_costos"] = centro_costos

        where_sql = " AND ".join(condiciones)

        sql = text(f"""
            SELECT 
                c.proveedor_nombre,
                c.idcompra AS factura,
                c.fecha,
                c.vencimiento,
                c.estado,  -- 👈 devuelve 'pagado' o 'pendiente'
                c.total,
                c.saldo,
                sc.nombre AS centro_costo_nombre
            FROM siigo_compras c
            LEFT JOIN siigo_centros_costo sc ON c.cost_center = sc.id
            WHERE {where_sql}
            ORDER BY c.fecha DESC
        """)
        rows = [dict(r) for r in db.session.execute(sql, params).mappings().all()]
        return jsonify(rows)


    # --- ENDPOINT 5: Detalle de facturas por proveedor ---
    @app.route("/reportes/financiero/compras-gastos/detalle-proveedor", methods=["GET"])
    @jwt_required()
    def detalle_proveedor():
        from sqlalchemy.sql import text
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        proveedor = request.args.get("proveedor")
        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        centro_costos = request.args.get("centro_costos")

        condiciones = ["c.idcliente = :idcliente", "c.proveedor_nombre = :proveedor"]
        params = {"idcliente": idcliente, "proveedor": proveedor}

        if desde:
            condiciones.append("c.fecha >= :desde")
            params["desde"] = desde
        if hasta:
            condiciones.append("c.fecha <= :hasta")
            params["hasta"] = hasta
        if centro_costos:
            condiciones.append("c.cost_center = :centro_costos")
            params["centro_costos"] = centro_costos

        where_sql = " AND ".join(condiciones)

        sql = text(f"""
            SELECT 
                c.idcompra,
                c.proveedor_nombre,
                c.factura_proveedor,
                c.fecha,
                c.vencimiento,
                c.total,
                c.saldo,
                c.estado, -- 👈 devuelve 'pagado' o 'pendiente'
                sc.nombre AS centro_costo_nombre
            FROM siigo_compras c
            LEFT JOIN siigo_centros_costo sc ON c.cost_center = sc.id
            WHERE {where_sql}
            ORDER BY c.fecha DESC
        """)
        rows = [dict(r) for r in db.session.execute(sql, params).mappings().all()]
        return jsonify(rows)




    # Endpoint para llamar Centros de costos enunciados en la BD de Siigo Compras
    @app.route("/catalogos/centros-costo-reales", methods=["GET"])
    @jwt_required()
    def catalogo_centros_costo_reales():
        from sqlalchemy.sql import text
        from datetime import datetime

        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")

        def validar_fecha(fecha_str):
            try:
                return datetime.strptime(fecha_str, "%Y-%m-%d").date()
            except Exception as e:
                app.logger.warning(f"⚠️ Fecha inválida: {fecha_str} — {e}")
                return None

        desde_valida = validar_fecha(desde) if desde else None
        hasta_valida = validar_fecha(hasta) if hasta else None

        condiciones = ["c.idcliente = :idcliente", "c.cost_center IS NOT NULL"]
        params = {"idcliente": idcliente}

        if desde_valida:
            condiciones.append("c.fecha >= :desde")
            params["desde"] = desde_valida
        if hasta_valida:
            condiciones.append("c.fecha <= :hasta")
            params["hasta"] = hasta_valida

        where_sql = " AND ".join(condiciones)

        sql = text(f"""
            SELECT DISTINCT
                c.cost_center AS id,
                COALESCE(cc.nombre, 'Sin centro de costo') AS nombre
            FROM siigo_compras c
            LEFT JOIN siigo_centros_costo cc ON c.cost_center = cc.id
            WHERE {where_sql}
            ORDER BY nombre
        """)

        try:
            app.logger.info(f"🔍 Ejecutando consulta de centros de costo reales — SQL: {sql} — Params: {params}")
            rows = [dict(r) for r in db.session.execute(sql, params).mappings().all()]
            return jsonify(rows)
        except Exception as e:
            app.logger.error(f"❌ Error al ejecutar consulta de centros-costo-reales — {e}", exc_info=True)
            return jsonify({
                "error": "Error interno al consultar centros de costo reales.",
                "detalle": str(e)
            }), 500




    # --- ENDPOINT: Reporte Financiero Consolidado ---
    # --- ENDPOINT: Reporte Financiero Consolidado (con Nómina) ---
    @app.route("/reportes/financiero/consolidado", methods=["GET"])
    @jwt_required()
    def reporte_financiero_consolidado():
        from sqlalchemy.sql import text
        from datetime import datetime

        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente"}), 403

        # -------- Filtros --------
        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        centro_costos = request.args.get("centro_costos")

        params = {"idcliente": idcliente}
        condiciones = ["idcliente = :idcliente"]

        def validar_fecha(fecha_str):
            try:
                return datetime.strptime(fecha_str, "%Y-%m-%d").date()
            except:
                return None

        fecha_desde_val = validar_fecha(desde)
        fecha_hasta_val = validar_fecha(hasta)

        if fecha_desde_val:
            condiciones.append("fecha >= :desde")
            params["desde"] = fecha_desde_val
        if fecha_hasta_val:
            condiciones.append("fecha <= :hasta")
            params["hasta"] = fecha_hasta_val
        if centro_costos:
            condiciones.append("cost_center = :centro_costos")
            params["centro_costos"] = centro_costos

        where_sql = " AND ".join(condiciones)

        # ---------------- Ingresos (ventas) ----------------
        sql_ingresos = text(f"""
            SELECT
                date_trunc('month', fecha) AS mes,
                SUM(COALESCE(total,0)) AS ingresos,
                SUM(COALESCE(subtotal,0)) AS ingresos_netos,
                COUNT(*) AS facturas_venta
            FROM facturas_enriquecidas
            WHERE {where_sql}
            GROUP BY mes
        """)
        ingresos_rows = db.session.execute(sql_ingresos, params).mappings().all()

        # ---------------- Egresos (compras/gastos) ----------------
        sql_egresos = text(f"""
            SELECT
                date_trunc('month', fecha) AS mes,
                SUM(COALESCE(total,0)) AS egresos,
                COUNT(*) AS facturas_compra
            FROM siigo_compras
            WHERE {where_sql}
            GROUP BY mes
        """)
        egresos_rows = db.session.execute(sql_egresos, params).mappings().all()

        # ---------------- Costos de Nómina ----------------
        condiciones_nomina = ["idcliente = :idcliente"]
        params_nomina = {"idcliente": idcliente}

        if fecha_desde_val:
            condiciones_nomina.append("periodo >= :desde_nomina")
            params_nomina["desde_nomina"] = fecha_desde_val
        if fecha_hasta_val:
            condiciones_nomina.append("periodo <= :hasta_nomina")
            params_nomina["hasta_nomina"] = fecha_hasta_val

        where_nomina = " AND ".join(condiciones_nomina)

        sql_nomina = text(f"""
            SELECT
                date_trunc('month', periodo) AS mes,
                SUM(COALESCE(total_ingresos,0)) AS nomina
            FROM siigo_nomina
            WHERE {where_nomina}
            GROUP BY mes
        """)
        nomina_rows = db.session.execute(sql_nomina, params_nomina).mappings().all()

        # Convertir a dict para fácil merge
        ingresos_dict = {str(r["mes"]): dict(r) for r in ingresos_rows}
        egresos_dict = {str(r["mes"]): dict(r) for r in egresos_rows}
        nomina_dict = {str(r["mes"]): dict(r) for r in nomina_rows}

        meses = sorted(set(ingresos_dict.keys()) | set(egresos_dict.keys()) | set(nomina_dict.keys()))

        # ---------------- Evolución combinada ----------------
        evolucion = []
        total_ingresos = total_egresos = facturas_venta = facturas_compra = 0
        total_nomina = 0
        utilidad_acumulada = 0

        for mes in meses:
            ing = ingresos_dict.get(mes, {"ingresos": 0, "facturas_venta": 0})
            egr = egresos_dict.get(mes, {"egresos": 0, "facturas_compra": 0})
            nom = nomina_dict.get(mes, {"nomina": 0})

            ingresos = ing["ingresos"] or 0
            ingresos_netos = ing.get("ingresos_netos", 0) or 0
            egresos = (egr["egresos"] or 0) + (nom["nomina"] or 0)
            nomina_mes = nom["nomina"] or 0

            utilidad = ingresos - egresos
            margen = (utilidad / ingresos * 100) if ingresos > 0 else 0

            utilidad_acumulada += utilidad

            evolucion.append({
                "mes": mes,
                "ingresos": ingresos,
                "egresos": egresos,
                "nomina": nomina_mes,
                "utilidad": utilidad,
                "margen": round(margen, 2),
                "utilidad_acumulada": utilidad_acumulada,
                "ingresos_netos": ingresos_netos,
            })

            total_ingresos += ingresos
            total_ingresos_netos = total_ingresos_netos + ingresos_netos if 'total_ingresos_netos' in locals() else ingresos_netos
            total_egresos += egresos
            total_nomina += nomina_mes
            facturas_venta += ing["facturas_venta"]
            facturas_compra += egr["facturas_compra"]

        # ---------------- KPIs globales ----------------
        utilidad_total = total_ingresos - total_egresos
        margen_total = (utilidad_total / total_ingresos * 100) if total_ingresos > 0 else 0

        kpis = {
            "ingresos": total_ingresos,
            "ingresos_netos": total_ingresos_netos,
            "egresos": total_egresos,
            "nomina": total_nomina,
            "utilidad": utilidad_total,
            "margen": round(margen_total, 2),
            "facturas_venta": facturas_venta,
            "facturas_compra": facturas_compra
        }

        # ---------------- Top Clientes ----------------
        sql_top_clientes = text(f"""
            SELECT 
                cliente_nombre AS nombre,
                COALESCE(SUM(total),0) AS total
            FROM facturas_enriquecidas
            WHERE {where_sql}
            GROUP BY cliente_nombre
            ORDER BY total DESC
            LIMIT 10
        """)
        top_clientes = [dict(r) for r in db.session.execute(sql_top_clientes, params).mappings().all()]

        # ---------------- Top Proveedores ----------------
        sql_top_proveedores = text(f"""
            SELECT 
                COALESCE(proveedor_nombre, 'Sin proveedor') AS nombre,
                COALESCE(SUM(total),0) AS total
            FROM siigo_compras
            WHERE {where_sql}
            GROUP BY COALESCE(proveedor_nombre, 'Sin proveedor')
            ORDER BY total DESC
            LIMIT 10
        """)
        top_proveedores = [dict(r) for r in db.session.execute(sql_top_proveedores, params).mappings().all()]

        return jsonify({
            "kpis": kpis,
            "evolucion": evolucion,
            "top_clientes": top_clientes,
            "top_proveedores": top_proveedores
        })






    # Para obtener factruas de cliente en el grafico de top 10 clientes pagina Consolidado
    @app.route("/reportes/facturas_cliente", methods=["GET"])
    @jwt_required()
    def facturas_por_cliente():
        from sqlalchemy.sql import text
        from datetime import datetime

        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente"}), 403

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        cliente = request.args.get("cliente")
        centro_costos = request.args.get("centro_costos")


        condiciones = ["idcliente = :idcliente"]
        params = {"idcliente": idcliente}

        def validar_fecha(fecha_str):
            try:
                return datetime.strptime(fecha_str, "%Y-%m-%d").date()
            except:
                return None

        if desde and validar_fecha(desde):
            condiciones.append("fecha >= :desde")
            params["desde"] = desde
        if hasta and validar_fecha(hasta):
            condiciones.append("fecha <= :hasta")
            params["hasta"] = hasta
        if cliente:
            condiciones.append("cliente_nombre = :cliente")
            params["cliente"] = cliente
        if centro_costos:
            condiciones.append("(cost_center = :centro_costos OR cost_center IS NULL)")
            params["centro_costos"] = centro_costos



        where_sql = " AND ".join(condiciones)

        sql = text(f"""
            SELECT *
            FROM facturas_enriquecidas
            WHERE {where_sql}
            ORDER BY fecha DESC
        """)

        rows = db.session.execute(sql, params).mappings().all()
        return jsonify({"rows": [dict(r) for r in rows]})


    # Para obtener factruas de proveedor en el grafico de top 10 proveedores pagina Consolidado
    # --- ENDPOINT: Facturas de proveedor (para modal) ---
    @app.route("/reportes/facturas_proveedor", methods=["GET"])
    @jwt_required()
    def facturas_por_proveedor():
        from sqlalchemy.sql import text
        from datetime import datetime

        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente"}), 403

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        proveedor = request.args.get("proveedor")
        centro_costos = request.args.get("centro_costos")

        condiciones = ["c.idcliente = :idcliente"]
        params = {"idcliente": idcliente}

        def validar_fecha(fecha_str):
            try:
                return datetime.strptime(fecha_str, "%Y-%m-%d").date()
            except:
                return None

        if desde and validar_fecha(desde):
            condiciones.append("c.fecha >= :desde")
            params["desde"] = desde
        if hasta and validar_fecha(hasta):
            condiciones.append("c.fecha <= :hasta")
            params["hasta"] = hasta
        if proveedor:
            condiciones.append("LOWER(COALESCE(c.proveedor_nombre, 'sin proveedor')) = LOWER(:proveedor)")
            params["proveedor"] = proveedor
        if centro_costos:
            condiciones.append("c.cost_center = :centro_costos")
            params["centro_costos"] = centro_costos

        where_sql = " AND ".join(condiciones)

        sql = text(f"""
            SELECT 
                c.idcompra,
                c.proveedor_nombre,
                c.factura_proveedor,
                c.fecha,
                c.vencimiento,
                c.total,
                c.saldo,
                cc.nombre AS centro_costo_nombre,
                CASE 
                    WHEN c.estado = 'pagado' THEN 'Pagada'
                    ELSE 'No Pagada'
                END AS estado
            FROM siigo_compras c
            LEFT JOIN siigo_centros_costo cc ON c.cost_center = cc.id
            WHERE {where_sql}
            ORDER BY c.fecha DESC
        """)

        rows = db.session.execute(sql, params).mappings().all()
        return jsonify({"rows": [dict(r) for r in rows]})



   # --- ENDPOINT: Catálogo de centros de costo para reporte consolidado ---
    @app.route("/catalogos/centros-costo-consolidado", methods=["GET"])
    @jwt_required()
    def catalogo_centros_costo_consolidado():
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        params = {"idcliente": idcliente}
        wh = ["f.idcliente = :idcliente"]

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")

        if desde:
            wh.append("f.fecha >= :desde")
            params["desde"] = desde
        if hasta:
            wh.append("f.fecha <= :hasta")
            params["hasta"] = hasta

        where_clause = " AND ".join(wh)

        sql = text(f"""
            SELECT DISTINCT
                f.cost_center AS id,
                COALESCE(f.centro_costo_nombre, 'Sin centro de costo') AS nombre
            FROM facturas_enriquecidas f
            WHERE {where_clause}
            AND f.cost_center IS NOT NULL
            ORDER BY nombre
        """)
        rows = [dict(r) for r in db.session.execute(sql, params).mappings().all()]
        return jsonify(rows)










    # ------------------------------------------
    # Cargar Documentos soporte desde archivo Excel
    # ------------------------------------------
    @app.route("/importar/soporte-excel", methods=["POST"])
    @jwt_required()
    def importar_documentos_soporte_desde_excel():
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente asociado"}), 400

        if "archivo" not in request.files:
            return jsonify({"error": "Archivo no proporcionado"}), 400

        file = request.files["archivo"]

        try:
            df = pd.read_excel(file, header=7)
            df.columns = df.columns.str.strip().str.replace('\xa0', ' ')
        except Exception as e:
            return jsonify({"error": f"No se pudo leer el Excel: {str(e)}"}), 400

        requeridos = ["Número comprobante", "Consecutivo", "Nombre tercero", "Centro costo", "Total", "Fecha elaboración", "Factura proveedor"]
        faltantes = [col for col in requeridos if col not in df.columns]
        if faltantes:
            return jsonify({"error": f"Faltan columnas requeridas: {', '.join(faltantes)}"}), 400

        centros_costo = {
            c.nombre.strip().upper(): c.id for c in SiigoCentroCosto.query.filter_by(idcliente=idcliente).all()
        }

        registros_creados = 0
        compras = {}
        compras_omitidas = []

        for _, row in df.iterrows():
            tipo_registro_raw = row.get("Tipo de registro", "")
            tipo_registro = str(tipo_registro_raw).replace('\xa0', ' ').replace('\ufeff', '').strip().lower()

            if tipo_registro != "secuencia":
                continue

            num_comprobante = str(row.get("Número comprobante", "")).split(".")[0]
            consecutivo = str(row.get("Consecutivo", "")).split(".")[0]
            idcompra = f"{num_comprobante}-{consecutivo}"

            if idcompra not in compras:
                existente = db.session.query(SiigoCompra).filter_by(idcliente=idcliente, idcompra=idcompra).first()
                if existente:
                    compras_omitidas.append(idcompra)
                    continue

                centro_costo_nombre = str(row.get("Centro costo", "")).strip().upper()
                cost_center = centros_costo.get(centro_costo_nombre)

                fecha_elab = pd.to_datetime(row["Fecha elaboración"], dayfirst=True)

                factura_proveedor = str(row.get("Factura proveedor", "")).strip().upper()

                if factura_proveedor.lower() in ("nan", "nat", ""):
                    factura_proveedor = None

                compra = SiigoCompra(
                    idcliente=idcliente,
                    idcompra=idcompra,
                    fecha=fecha_elab.date(),
                    vencimiento=pd.to_datetime(row.get("Fecha vencimiento"), errors="coerce", dayfirst=True).date() if row.get("Fecha vencimiento") else None,
                    proveedor_nombre=str(row.get("Nombre tercero", "")).strip(),
                    proveedor_identificacion=str(row.get("Identificación", "")).strip().split('.')[0],
                    estado=None,
                    total=float(row.get("Total", 0) or 0),
                    saldo=0,
                    cost_center=cost_center,
                    creado=fecha_elab + pd.Timedelta(minutes=15),
                    factura_proveedor=factura_proveedor  # <- NUEVO
                )

                db.session.add(compra)
                db.session.flush()
                compras[idcompra] = compra.id
                registros_creados += 1

            compra_id = compras[idcompra]
            impuestos = float(row.get("Valor Impuesto Cargo", 0) or 0) + float(row.get("Valor Impuesto", 0) or 0)

            item = SiigoCompraItem(
                compra_id=compra_id,
                idcliente=idcliente,  # ✅ importante
                descripcion=str(row.get("Nombre", "")).strip(),
                cantidad=float(row.get("Cantidad", 0) or 0),
                precio=float(row.get("Total", 0) or 0),
                impuestos=impuestos,
                codigo="" if pd.isna(row.get("Código", "")) else str(row.get("Código", "")).strip()
            )
            db.session.add(item)

        db.session.commit()

        return jsonify({
            "mensaje": f"Importación completada. Compras creadas: {registros_creados}",
            "omitidas": compras_omitidas
        })




    # Cargar Documentos soporte desde archivo Excel para exportarlo a un ZIP con dos archivos Excel (preview)
    @app.route("/importar/soporte-excel-preview", methods=["POST"])
    @jwt_required()
    def importar_documentos_soporte_desde_excel_preview():
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente asociado"}), 400

        if "archivo" not in request.files:
            return jsonify({"error": "Archivo no proporcionado"}), 400

        file = request.files["archivo"]

        try:
            df = pd.read_excel(file, header=7)
            df.columns = df.columns.str.strip().str.replace('\xa0', ' ')
            print("🧩 Columnas detectadas:", df.columns.tolist())
        except Exception as e:
            return jsonify({"error": f"No se pudo leer el Excel: {str(e)}"}), 400

        requeridos = ["Número comprobante", "Consecutivo", "Nombre tercero", "Centro costo", "Total", "Fecha creación"]
        faltantes = [col for col in requeridos if col not in df.columns]
        if faltantes:
            return jsonify({"error": f"Faltan columnas requeridas: {', '.join(faltantes)}"}), 400

        centros_costo = {
            c.nombre.strip().upper(): c.id for c in SiigoCentroCosto.query.filter_by(idcliente=idcliente).all()
        }

        compras_preview = []
        items_preview = []
        compras = {}

        for _, row in df.iterrows():
            tipo_registro_raw = row.get("Tipo de registro", "")
            tipo_registro = str(tipo_registro_raw).replace('\xa0', ' ').replace('\ufeff', '').strip().lower()
            print(f"🧪 Tipo de registro detectado: '{tipo_registro}' (original: {repr(tipo_registro_raw)})")

            if tipo_registro != "secuencia":
                continue

            idcompra = f"{str(row['Número comprobante']).strip()}-{str(row['Consecutivo']).strip()}"

            if idcompra not in compras:
                centro_costo_nombre = str(row.get("Centro costo", "")).strip().upper()
                cost_center = centros_costo.get(centro_costo_nombre)

                compras[idcompra] = len(compras) + 1  # Fake ID

                compras_preview.append({
                    "idcliente": idcliente,
                    "idcompra": idcompra,
                    "fecha": pd.to_datetime(row["Fecha creación"]).date(),
                    "vencimiento": pd.to_datetime(row.get("Fecha vencimiento"), errors="coerce").date() if row.get("Fecha vencimiento") else None,
                    "proveedor_nombre": str(row.get("Nombre tercero", "")).strip(),
                    "proveedor_identificacion": str(row.get("Identificación", "")).strip().split('.')[0],
                    "estado": None,
                    "total": float(row.get("Total", 0) or 0),
                    "saldo": 0,
                    "cost_center": cost_center,
                    "creado": pd.to_datetime(row["Fecha creación"]) + pd.Timedelta(minutes=15)
                })

            compra_id = compras[idcompra]

            impuestos = float(row.get("Valor Impuesto Cargo", 0) or 0) + float(row.get("Valor Impuesto", 0) or 0)

            items_preview.append({
                "compra_id": compra_id,
                "descripcion": str(row.get("Nombre", "")).strip(),
                "cantidad": float(row.get("Cantidad", 0) or 0),
                "precio": float(row.get("Total", 0) or 0),
                "impuestos": impuestos,
                "codigo": "" if pd.isna(row.get("Código", "")) else str(row.get("Código", "")).strip()
            })

        # Exportar a Excel en memoria
        compras_df = pd.DataFrame(compras_preview)
        items_df = pd.DataFrame(items_preview)

        in_memory_zip = BytesIO()
        with zipfile.ZipFile(in_memory_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            compras_buffer = BytesIO()
            items_buffer = BytesIO()

            compras_df.to_excel(compras_buffer, index=False)
            items_df.to_excel(items_buffer, index=False)

            zf.writestr("preview_siigo_compras.xlsx", compras_buffer.getvalue())
            zf.writestr("preview_siigo_compras_items.xlsx", items_buffer.getvalue())

        in_memory_zip.seek(0)
        return send_file(
            in_memory_zip,
            mimetype="application/zip",
            as_attachment=True,
            download_name="preview_siigo_compras.zip"
        )




    # Endpoint para validar cuentas por pagar vs Siigo
    @app.route("/debug/siigo/accounts-payable-check", methods=["GET"])
    @jwt_required()
    def siigo_accounts_payable_check():
        import requests
        from sqlalchemy.sql import text
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        # ⚠️ Tu token de Siigo (ajusta según lo tengas guardado)
        siigo_token = "Bearer TU_TOKEN_SIIGO_AQUI"

        try:
            # Paso 1: Llamar API de Siigo
            response = requests.get(
                "https://api.siigo.com/v1/reports/accounts-payable",
                headers={"Authorization": siigo_token}
            )
            response.raise_for_status()
            siigo_data = response.json()
        except Exception as e:
            return jsonify({"error": f"Error consultando Siigo: {str(e)}"}), 500

        # Paso 2: Limpiar y normalizar data del API Siigo
        siigo_map = []
        for item in siigo_data:
            siigo_map.append({
                "proveedor": item.get("provider", "").strip().upper(),
                "factura": item.get("document_number", "").strip().upper(),
                "saldo_api": float(item.get("balance", 0)),
                "total_api": float(item.get("total", 0)),
                "fecha": item.get("issue_date"),
                "vencimiento": item.get("due_date")
            })

        # Paso 3: Cargar todas tus facturas locales en un mapa rápido
        sql = text("""
            SELECT 
                proveedor_nombre, idcompra, saldo, total
            FROM siigo_compras
            WHERE idcliente = :idcliente
        """)
        local_facturas = {
            row["idcompra"].strip().upper(): {
                "proveedor": row["proveedor_nombre"].strip().upper(),
                "saldo_local": float(row["saldo"]),
                "total_local": float(row["total"])
            }
            for row in db.session.execute(sql, {"idcliente": idcliente}).mappings().all()
        }

        # Paso 4: Comparar y buscar discrepancias
        discrepancias = []
        for item in siigo_map:
            factura = item["factura"]
            match = local_facturas.get(factura)

            if match:
                delta_saldo = abs(match["saldo_local"] - item["saldo_api"])
                if delta_saldo > 10:  # margen mínimo de diferencia
                    discrepancias.append({
                        "factura": factura,
                        "proveedor_siigo": item["proveedor"],
                        "proveedor_local": match["proveedor"],
                        "saldo_api": item["saldo_api"],
                        "saldo_local": match["saldo_local"],
                        "diferencia": delta_saldo
                    })
            else:
                discrepancias.append({
                    "factura": factura,
                    "proveedor_siigo": item["proveedor"],
                    "proveedor_local": "No encontrada",
                    "saldo_api": item["saldo_api"],
                    "saldo_local": None,
                    "diferencia": None
                })

        return jsonify({
            "total_siigo": len(siigo_map),
            "coincidencias": len(siigo_map) - len(discrepancias),
            "discrepancias": discrepancias
        })


    # Endpoint para obtener cuentas por pagar raw desde Siigo (para debug)
    @app.route("/debug/siigo/accounts-payable-raw", methods=["GET"])
    @jwt_required()
    def siigo_accounts_payable_raw():
        from flask import jsonify
        import requests

        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "ID cliente no encontrado en JWT"}), 401

        cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cred:
            return jsonify({"error": "Credenciales de Siigo no encontradas para este cliente"}), 404

        access_key = dec(cred.client_secret)
        if not access_key:
            return jsonify({"error": "No se pudo desencriptar client_secret"}), 500

        try:
            # Obtener token
            token_data = siigo_auth_json(cred.base_url, cred.client_id, access_key)
            token = token_data["access_token"]

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            }

            if cred.partner_id:
                headers["Partner-Id"] = cred.partner_id

            all_items = []
            page = 1
            page_size = 100  # máximo permitido en la mayoría de APIs
            base_url = cred.base_url.rstrip('/')

            while True:
                url = f"{base_url}/v1/accounts-payable?page={page}&page_size={page_size}"
                res = requests.get(url, headers=headers)

                if not res.ok:
                    return jsonify({
                        "error": f"Error desde Siigo (página {page})",
                        "detalle": res.text,
                        "headers": dict(res.headers),
                        "url_usada": url
                    }), res.status_code

                data = res.json()
                results = data.get("results", [])
                all_items.extend(results)

                # Verificar si hay siguiente página
                next_link = data.get("_links", {}).get("next", {}).get("href")
                if not next_link:
                    break  # no hay más páginas

                page += 1

            # 🔁 Transformamos los resultados al formato esperado por el frontend
            transformed = []
            for item in all_items:
                transformed.append({
                    "document": f'{item["due"]["prefix"]}-{item["due"]["consecutive"]}',
                    "date": item["due"]["date"],
                    "due_date": item["due"]["date"],  # seguimos usando la misma
                    "supplier": {
                        "identification": item["provider"]["identification"],
                        "name": item["provider"]["name"],
                    },
                    "amount": item["due"]["balance"],  # usamos el mismo valor como monto
                    "balance": item["due"]["balance"],
                    "cost_center": item.get("cost_center", {}).get("name"),
                })

            return jsonify(transformed)

        except Exception as e:
            return jsonify({
                "error": "Error interno al consultar Siigo",
                "detalle": str(e)
            }), 500



    # 1. Para Botón 1 - Sincronizar cuentas por pagar desde Siigo
    @app.route("/siigo/sync-accounts-payable", methods=["POST"])
    
    def sync_accounts_payable():
        idcliente = obtener_idcliente_desde_request()
        if not idcliente:
            return jsonify({"error": "Cliente no autorizado"}), 403
        
        cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cred:
            return jsonify({"error": "Credenciales no encontradas"}), 404

        access_key = dec(cred.client_secret)
        token_data = siigo_auth_json(cred.base_url, cred.client_id, access_key)
        token = token_data["access_token"]

        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if cred.partner_id:
            headers["Partner-Id"] = cred.partner_id

        url = f"{cred.base_url.rstrip('/')}/v1/accounts-payable?page=1&page_size=100"
        
        all_results = []
        while url:
            res = requests.get(url, headers=headers)
            data = res.json()
            all_results.extend(data.get("results", []))
            url = data.get("_links", {}).get("next", {}).get("href")

        # Limpiar registros previos de este cliente
        SiigoCuentasPorCobrar.query.filter_by(idcliente=idcliente).delete()

        # Insertar nuevos registros (sin fecha/idcompra todavía)
        for item in all_results:
            row = SiigoCuentasPorCobrar(
                idcliente=idcliente,
                documento=f"{item['due']['prefix']}-{item['due']['consecutive']}",
                fecha=None,  # pendiente hasta el cruce
                fecha_vencimiento=item["due"]["date"],
                proveedor_identificacion=item["provider"]["identification"],
                proveedor_nombre=item["provider"]["name"],
                valor=item["due"]["balance"],
                saldo=item["due"]["balance"],
                centro_costo=item.get("cost_center", {}).get("name")
            )
            db.session.add(row)

        db.session.commit()
        return jsonify({"mensaje": f"{len(all_results)} registros de cuentas por pagar sincronizados."})


    # 2. Cruce con compras locales
    # --- ENDPOINT: Cruce de cuentas por pagar con compras locales ---
    @app.route("/siigo/cross-accounts-payable", methods=["POST"])
    
    def cross_accounts_payable():
        from sqlalchemy import func

        idcliente = obtener_idcliente_desde_request()
        if not idcliente:
            return jsonify({"error": "Cliente no autorizado"}), 403


        # --- Paso 1: Traer las cuentas pendientes desde Siigo (API /v1/accounts-payable) ---
        cuentas = SiigoCuentasPorCobrar.query.filter_by(idcliente=idcliente).all()

        # --- Paso 2: Traer las compras locales ---
        compras = {
            (c.factura_proveedor, c.proveedor_identificacion): (c.idcompra, c.fecha)
            for c in SiigoCompra.query.filter_by(idcliente=idcliente).all()
        }

        matched, total = 0, len(cuentas)
        cuentas_keys = set()

        # --- Paso 3: Cruce positivo (pendientes) ---
        for cuenta in cuentas:
            key = (cuenta.documento, cuenta.proveedor_identificacion)
            cuentas_keys.add(key)

            if key in compras:
                idcompra, fecha = compras[key]
                cuenta.idcompra, cuenta.fecha = idcompra, fecha

                compra = SiigoCompra.query.filter_by(idcliente=idcliente, idcompra=idcompra).first()
                if compra:
                    compra.estado = "pendiente"
                    compra.saldo = cuenta.saldo  # Actualizar saldo directo desde Siigo
                matched += 1

        # --- Paso 4: Cruce negativo (ya no están pendientes en Siigo) ---
        compras_keys = set(compras.keys())
        pagadas = compras_keys - cuentas_keys

        for key in pagadas:
            idcompra, _ = compras[key]
            compra = SiigoCompra.query.filter_by(idcliente=idcliente, idcompra=idcompra).first()
            if compra:
                compra.estado = "pagado"
                compra.saldo = 0  # aseguramos saldo cero

        # --- Paso 5: Ajuste especial para Documentos Soporte (DS) ---
        from sqlalchemy import func, or_

        ds_compras = SiigoCompra.query.filter(
            SiigoCompra.idcliente == idcliente,
            SiigoCompra.idcompra.like("DS%")
        ).all()

        ds_ajustadas = 0
        detalles_ajuste = {}

        for compra in ds_compras:
            total_pagado = db.session.query(func.sum(SiigoPagoProveedor.valor)).filter(
                SiigoPagoProveedor.idcliente == idcliente,
                or_(
                    func.trim(func.upper(SiigoPagoProveedor.factura_aplicada)) == func.trim(func.upper(compra.idcompra)),
                    func.trim(func.upper(SiigoPagoProveedor.factura_aplicada)) == func.trim(func.upper(compra.factura_proveedor))
                ),
                SiigoPagoProveedor.proveedor_identificacion == compra.proveedor_identificacion
            ).scalar() or 0

            if total_pagado > 0:
                nuevo_saldo = max(float(compra.total or 0) - float(total_pagado), 0)
                compra.saldo = nuevo_saldo

                if nuevo_saldo == 0:
                    compra.estado = "pagado"
                elif nuevo_saldo < float(compra.total or 0):
                    compra.estado = "parcial"
                else:
                    compra.estado = "pendiente"

                ds_ajustadas += 1
                detalles_ajuste[str(compra.idcompra)] = {
                    "factura_proveedor": str(compra.factura_proveedor or ""),
                    "total": float(compra.total or 0),
                    "pagado": float(total_pagado),
                    "saldo": float(nuevo_saldo),
                    "estado": str(compra.estado or "")
                }

        db.session.commit()

        return jsonify({
            "mensaje": (
                f"Cruce completado. {matched}/{total} cuentas vinculadas. "
                f"{len(pagadas)} marcadas como pagadas. "
                f"{ds_ajustadas} DS ajustadas por pagos reales."
            ),
            "detalles_ds": detalles_ajuste
        })



    # --- Importar info de Nómina desde Archivo Excel ---
    # --- Importar info de Nómina desde Archivo Excel ---
    @app.route("/importar/nomina-excel", methods=["POST"])
    @jwt_required()
    def importar_nomina_desde_excel():
        import pandas as pd
        from datetime import date

        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente asociado"}), 400

        if "archivo" not in request.files:
            return jsonify({"error": "Archivo no proporcionado"}), 400

        # --- Leer parámetros de periodo ---
        mes = request.form.get("mes")
        anio = request.form.get("anio")

        if not mes or not anio:
            return jsonify({"error": "Debe indicar mes y año de la nómina"}), 400

        try:
            periodo = date(int(anio), int(mes), 1)  # 👈 Generamos periodo YYYY-MM-01
        except Exception:
            return jsonify({"error": "Mes o año inválido"}), 400

        file = request.files["archivo"]

        try:
            # ✅ Usamos calamine para evitar el bug de celdas combinadas
            df_raw = pd.read_excel(file, header=None, engine="calamine")

            # La fila 6 (índice 5 en 0-based) son los headers
            headers = df_raw.iloc[5].tolist()
            headers = [str(h).strip().replace("\xa0", " ") for h in headers]

            # Desde fila 7 en adelante
            df = df_raw.iloc[6:].copy()
            df.columns = headers
            df = df.dropna(how="all")

            # 🔹 Reemplazar NaN por None para que no falle JSON ni DB
            df = df.where(pd.notnull(df), None)

            print("✅ Encabezados detectados:", headers)
            print("✅ Total filas a importar:", len(df))

        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({"error": f"No se pudo leer el Excel: {str(e)}"}), 400

        registros_creados = 0
        errores = []

        for idx, row in df.iterrows():
            try:
                registro = SiigoNomina(
                    idcliente=idcliente,
                    periodo=periodo,
                    nombre=str(row.get("Nombre", "")),
                    identificacion=str(row.get("Identificación", "")),
                    no_contrato=str(row.get("No contrato", "")),
                    sueldo=row.get("Sueldo") or 0,
                    aux_transporte=row.get("Aux. de transporte/Aux. de conectividad digital") or 0,
                    prov_vacaciones=row.get("Provision Mensual Vacaciones") or 0,
                    prov_prima=row.get("Provision Mensual Prima") or 0,
                    prov_intereses_cesantias=row.get("Provision Mensual Intereses a las Cesantias") or 0,
                    prov_cesantias=row.get("Provision Mensual Cesantias") or 0,
                    auxilio_extralegal=row.get("Auxilio extralegal") or 0,
                    total_ingresos=row.get("Total Ingresos") or 0,
                    fondo_salud=row.get("Fondo de salud") or 0,
                    fondo_pension=row.get("Fondo de pensión") or 0,
                    fondo_solidaridad=row.get("Fondo de solidaridad pensional") or 0,
                    retefuente=row.get("Retefuente") or 0,
                    prestamos=row.get("Prestamos") or 0,
                    total_deducciones=row.get("Total deducciones") or 0,
                    neto_pagar=row.get("Neto a Pagar") or 0,
                )
                db.session.add(registro)
                registros_creados += 1
            except Exception as e:
                errores.append(f"Fila {idx+7}: {e}")  # +7 porque los datos empiezan en la fila 7

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": f"Error al guardar en BD: {str(e)}"}), 500

        return jsonify({
            "mensaje": f"Nómina {periodo.strftime('%B %Y')} importada.",
            "registros_creados": registros_creados,
            "errores": errores[:5]  # mostramos hasta 5 errores como preview
        })





    # --- VALIDAR archivo de Nómina antes de importar ---
    # --- ENDPOINT de validación de Excel de Nómina ---
    @app.route("/validar/nomina-excel", methods=["POST"])
    @jwt_required()
    def validar_nomina_excel():
        import pandas as pd

        if "archivo" not in request.files:
            return jsonify({"error": "Archivo no proporcionado"}), 400

        file = request.files["archivo"]

        try:
            # Usamos calamine (más robusto con merges)
            df_raw = pd.read_excel(file, header=None, engine="calamine")

            # La fila 6 (índice 5 en 0-based) son los headers
            headers = df_raw.iloc[5].tolist()
            headers = [str(h).strip().replace("\xa0", " ") for h in headers]

            # Desde fila 7 en adelante
            df = df_raw.iloc[6:].copy()
            df.columns = headers
            df = df.dropna(how="all")

            # 🔹 Reemplazar NaN por None para que sea JSON válido
            df = df.where(pd.notnull(df), None)

            # Previsualización de las primeras filas
            preview = df.head(10).to_dict(orient="records")

        except Exception as e:
            return jsonify({"error": f"No se pudo leer el Excel: {str(e)}"}), 400

        return jsonify({
            "mensaje": f"Archivo leído correctamente. {len(preview)} filas en preview.",
            "preview": preview
        })



    # --- ENDPOINT: Reporte Dashboard de Nómina ---
    # --- ENDPOINT: Reporte Dashboard de Nómina (extendido con rango de fechas) ---
    @app.route("/reportes/nomina/dashboard", methods=["GET"])
    @jwt_required()
    def reporte_nomina_dashboard():
        from sqlalchemy.sql import text
        from datetime import datetime

        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente"}), 403

        # --- Parámetros de filtro ---
        mes = request.args.get("mes")
        anio = request.args.get("anio")
        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        empleado = request.args.get("empleado")

        condiciones = ["idcliente = :idcliente"]
        params = {"idcliente": idcliente}

        # --- Filtros inteligentes ---
        try:
            # Filtro por año y/o mes (mantiene compatibilidad con versión anterior)
            if anio and anio.strip() and anio != "0":
                condiciones.append("EXTRACT(YEAR FROM periodo) = :anio")
                params["anio"] = int(anio)

            if mes and mes.strip() and mes != "0":
                condiciones.append("EXTRACT(MONTH FROM periodo) = :mes")
                params["mes"] = int(mes)

            # --- Filtro por rango de fechas (tiene prioridad sobre año/mes si ambos están presentes)
            if desde and hasta:
                try:
                    desde_dt = datetime.strptime(desde, "%Y-%m-%d").date()
                    hasta_dt = datetime.strptime(hasta, "%Y-%m-%d").date()
                    condiciones.append("periodo BETWEEN :desde AND :hasta")
                    params["desde"] = desde_dt
                    params["hasta"] = hasta_dt
                except ValueError:
                    return jsonify({"error": "Formato de fecha inválido. Use YYYY-MM-DD"}), 400

            # --- Filtro opcional por empleado ---
            if empleado and empleado.strip():
                condiciones.append("identificacion = :empleado")
                params["empleado"] = empleado

        except Exception as e:
            print(f"[ERROR filtros nómina] {e}")
            return jsonify({"error": "Parámetros inválidos"}), 400

        where_sql = " AND ".join(condiciones)

        # --- KPIs globales ---
        sql_global = text(f"""
            SELECT
                COUNT(DISTINCT identificacion) AS empleados,
                SUM(sueldo) AS total_sueldos,
                SUM(aux_transporte) AS total_auxilios,
                SUM(prov_vacaciones) AS total_vacaciones,
                SUM(prov_prima) AS total_primas,
                SUM(prov_intereses_cesantias) AS total_intereses_cesantias,
                SUM(prov_cesantias) AS total_cesantias,
                SUM(auxilio_extralegal) AS total_extralegal,
                SUM(total_ingresos) AS total_ingresos,
                SUM(fondo_salud) AS total_salud,
                SUM(fondo_pension) AS total_pension,
                SUM(fondo_solidaridad) AS total_solidaridad,
                SUM(retefuente) AS total_retefuente,
                SUM(prestamos) AS total_prestamos,
                SUM(total_deducciones) AS total_deducciones,
                SUM(neto_pagar) AS total_neto_pagar
            FROM siigo_nomina
            WHERE {where_sql}
        """)
        globales = db.session.execute(sql_global, params).mappings().first()

        # --- Totales por empleado ---
        sql_por_empleado = text(f"""
            SELECT
                nombre,
                identificacion,
                SUM(sueldo) AS sueldo,
                SUM(aux_transporte) AS aux_transporte,
                SUM(prov_vacaciones) AS prov_vacaciones,
                SUM(prov_prima) AS prov_prima,
                SUM(prov_intereses_cesantias) AS prov_intereses_cesantias,
                SUM(prov_cesantias) AS prov_cesantias,
                SUM(auxilio_extralegal) AS auxilio_extralegal,
                SUM(total_ingresos) AS total_ingresos,
                SUM(fondo_salud) AS fondo_salud,
                SUM(fondo_pension) AS fondo_pension,
                SUM(fondo_solidaridad) AS fondo_solidaridad,
                SUM(retefuente) AS retefuente,
                SUM(prestamos) AS prestamos,
                SUM(total_deducciones) AS total_deducciones,
                SUM(neto_pagar) AS neto_pagar
            FROM siigo_nomina
            WHERE {where_sql}
            GROUP BY nombre, identificacion
            ORDER BY SUM(neto_pagar) DESC
        """)
        empleados = [dict(r) for r in db.session.execute(sql_por_empleado, params).mappings().all()]

        # --- Top empleados por costo ---
        top_empleados = sorted(empleados, key=lambda x: x["neto_pagar"] or 0, reverse=True)[:10]

        return jsonify({
            "globales": dict(globales) if globales else {},
            "empleados": empleados,
            "top_empleados": top_empleados
        })




    ############ ENDPOINTS PRODUCTOS ############
    @app.route("/siigo/sync-productos", methods=["POST"])
    
    def siigo_sync_productos():
        idcliente = obtener_idcliente_desde_request()
        if not idcliente:
            return jsonify({"error": "Cliente no autorizado"}), 403

        try:
            from siigo.siigo_sync_productos import sync_productos_desde_siigo
            mensaje = sync_productos_desde_siigo(idcliente)
            return jsonify({"mensaje": mensaje})
        except Exception as e:
            return jsonify({"error": str(e)}), 500





    # Debug: traer productos en bruto desde Siigo (sin JWT)
    @app.route("/siigo/debug-productos-raw", methods=["GET"])
    def siigo_debug_productos_raw():
        import requests
        from siigo.siigo_sync_refactor import siigo_auth_json, dec_local, _headers_bearer
        from models import SiigoCredencial

        idcliente = request.args.get("idcliente", type=int)
        if not idcliente:
            return jsonify({"error": "Falta idcliente"}), 400

        # --- credenciales ---
        cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cred:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        access_key = dec_local(cred.client_secret)
        if not access_key:
            return jsonify({"error": "No se pudo desencriptar Access Key"}), 400

        # --- token ---
        token_data = siigo_auth_json(base_url=cred.base_url, username=cred.client_id, access_key=access_key)
        token = token_data.get("access_token")
        headers = _headers_bearer(token)
        base_url = cred.base_url.rstrip("/")

        # --- recorrer productos con paginación ---
        all_productos = []
        page = 1
        page_size = 50
        while True:
            url = f"{base_url}/v1/products?page={page}&page_size={page_size}"
            r = requests.get(url, headers=headers, timeout=60)
            if r.status_code != 200:
                return jsonify({"error": f"Error {r.status_code}", "detalle": r.text}), 500
            data = r.json() or {}
            results = data.get("results") or []
            all_productos.extend(results)

            # salir si no hay más páginas
            if len(results) < page_size:
                break
            page += 1

        return jsonify({"productos": all_productos})



    # --- Reporte: Dashboard de Vendedores ---
    # --- Reporte de Vendedores ---
    @app.route("/reportes/vendedores", methods=["GET"])
    @jwt_required()
    def reportes_vendedores():
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente asociado"}), 400

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        centro_costos = request.args.get("centro_costos")

        filtros = ["f.idcliente = :idcliente", "f.estado_pago = 'pagada'"]
        params = {"idcliente": idcliente}

        if desde:
            filtros.append("f.fecha >= :desde")
            params["desde"] = desde
        if hasta:
            filtros.append("f.fecha <= :hasta")
            params["hasta"] = hasta
        if centro_costos:
            filtros.append("f.cost_center = :centro_costos")  # 👈 nombre correcto
            params["centro_costos"] = centro_costos

        filtro_sql = " AND ".join(filtros)

        # KPIs
        sql_kpis = f"""
            SELECT
                COALESCE(SUM(f.total),0) AS ventas_totales,
                COUNT(*) AS facturas,
                CASE WHEN COUNT(*) > 0 THEN ROUND(SUM(f.total)/COUNT(*),2) ELSE 0 END AS ticket_promedio
            FROM facturas_enriquecidas f
            WHERE {filtro_sql}
        """
        kpis = db.session.execute(text(sql_kpis), params).mappings().first()

        # Top 5 vendedores
        sql_top = f"""
            SELECT
                COALESCE(f.vendedor_nombre, 'Sin asignar') AS vendedor_nombre,
                SUM(f.total) AS total,
                COUNT(*) AS facturas
            FROM facturas_enriquecidas f
            WHERE {filtro_sql}
            GROUP BY COALESCE(f.vendedor_nombre, 'Sin asignar')
            ORDER BY total DESC
            LIMIT 5
        """
        top5 = db.session.execute(text(sql_top), params).mappings().all()

        # Ranking completo
        sql_rank = f"""
            SELECT
                COALESCE(f.vendedor_nombre, 'Sin asignar') AS vendedor_nombre,
                SUM(f.total) AS total,
                COUNT(*) AS facturas
            FROM facturas_enriquecidas f
            WHERE {filtro_sql}
            GROUP BY COALESCE(f.vendedor_nombre, 'Sin asignar')
            ORDER BY total DESC
        """
        ranking = db.session.execute(text(sql_rank), params).mappings().all()

        return jsonify({
            "kpis": dict(kpis) if kpis else {},
            "top5": [dict(r) for r in top5],
            "ranking": [dict(r) for r in ranking]
        })





    # --- Reporte: Dashboard de Productos ---

    # --- Reporte de Productos ---
    @app.route("/reportes/productos", methods=["GET"])
    @jwt_required()
    def reportes_productos():
        claims = get_jwt()
        idcliente = claims.get("idcliente")

        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        centro_costo = request.args.get("centro_costo")  # ✅ ahora es nombre, no id
        producto_code = request.args.get("producto_code")  # ✅ filtro adicional
        ordenar_por = request.args.get("ordenar_por", "cantidad")  # cantidad | total

        filtros = ["f.idcliente = :idcliente", "f.estado_pago = 'pagada'"]
        params = {"idcliente": idcliente}

        if desde:
            filtros.append("f.fecha >= :desde")
            params["desde"] = desde
        if hasta:
            filtros.append("f.fecha <= :hasta")
            params["hasta"] = hasta
        if centro_costo:  # ✅ usamos nombre, no id
            filtros.append("f.centro_costo_nombre = :centro_costo")
            params["centro_costo"] = centro_costo
        if producto_code:
            filtros.append("i.producto_id = :producto_code")
            params["producto_code"] = producto_code

        where = " AND ".join(filtros)
        columna_orden = "SUM(i.cantidad)" if ordenar_por == "cantidad" else "SUM(i.total_item)"

        # --- KPIs ---
        sql_kpis = text(f"""
            SELECT
                COALESCE(SUM(i.total_item),0) AS ventas_totales,
                COUNT(DISTINCT f.factura_id) AS facturas,
                CASE WHEN COUNT(DISTINCT f.factura_id) > 0
                    THEN SUM(i.total_item) / COUNT(DISTINCT f.factura_id)
                    ELSE 0 END AS ticket_promedio
            FROM siigo_factura_items i
            JOIN facturas_enriquecidas f ON f.factura_id = i.factura_id
            WHERE {where}
        """)
        kpis = dict(db.session.execute(sql_kpis, params).mappings().first() or {})

        # --- Top 10 ---
        sql_top = text(f"""
            SELECT p.code, p.name as producto, SUM(i.cantidad) as cantidad, SUM(i.total_item) as total
            FROM siigo_factura_items i
            JOIN facturas_enriquecidas f ON f.factura_id = i.factura_id
            JOIN siigo_productos p ON p.code = i.producto_id AND p.idcliente = f.idcliente
            WHERE {where}
            GROUP BY p.code, p.name
            ORDER BY {columna_orden} DESC
            LIMIT 10
        """)
        top10 = [dict(r) for r in db.session.execute(sql_top, params).mappings().all()]

        # --- Bottom 10 ---
        sql_bottom = text(f"""
            SELECT p.code, p.name as producto, SUM(i.cantidad) as cantidad, SUM(i.total_item) as total
            FROM siigo_factura_items i
            JOIN facturas_enriquecidas f ON f.factura_id = i.factura_id
            JOIN siigo_productos p ON p.code = i.producto_id AND p.idcliente = f.idcliente
            WHERE {where}
            GROUP BY p.code, p.name
            ORDER BY {columna_orden} ASC
            LIMIT 10
        """)
        bottom10 = [dict(r) for r in db.session.execute(sql_bottom, params).mappings().all()]

        return jsonify({"kpis": kpis, "top10": top10, "bottom10": bottom10})



    # --- Catálogo de productos disponibles (para el filtro) ---
    @app.route("/catalogos/productos", methods=["GET"])
    @jwt_required()
    def catalogo_productos():
        claims = get_jwt()
        idcliente = claims.get("idcliente")

        sql = text("""
            SELECT DISTINCT p.code, p.name
            FROM siigo_factura_items i
            JOIN facturas_enriquecidas f ON f.factura_id = i.factura_id
            JOIN siigo_productos p ON p.code = i.producto_id AND p.idcliente = f.idcliente
            WHERE f.idcliente = :idcliente
            ORDER BY p.code
        """)
        rows = db.session.execute(sql, {"idcliente": idcliente}).mappings().all()
        return jsonify([{"code": r["code"], "name": r["name"], "label": f"{r['code']} - {r['name']}"} for r in rows])


    # --- Detalle producto con histórico mensual ---
    @app.route("/reportes/productos/detalle", methods=["GET"])
    @jwt_required()
    def detalle_producto():
        claims = get_jwt()
        idcliente = claims.get("idcliente")

        producto_code = request.args.get("producto_code")
        desde = request.args.get("desde")
        hasta = request.args.get("hasta")
        centro_costo = request.args.get("centro_costo")

        if not producto_code:
            return jsonify({"error": "Falta producto_code"}), 400

        filtros = ["f.idcliente = :idcliente", "f.estado_pago = 'pagada'", "i.producto_id = :producto_code"]
        params = {"idcliente": idcliente, "producto_code": producto_code}

        if desde:
            filtros.append("f.fecha >= :desde")
            params["desde"] = desde
        if hasta:
            filtros.append("f.fecha <= :hasta")
            params["hasta"] = hasta
        if centro_costo:
            filtros.append("f.centro_costo_nombre = :centro_costo")
            params["centro_costo"] = centro_costo

        where = " AND ".join(filtros)

        # --- Totales ---
        sql_totales = text(f"""
            SELECT p.code, p.name as producto,
                SUM(i.cantidad) as cantidad,
                SUM(i.total_item) as total,
                COUNT(DISTINCT f.factura_id) as facturas
            FROM siigo_factura_items i
            JOIN facturas_enriquecidas f ON f.factura_id = i.factura_id
            JOIN siigo_productos p ON p.code = i.producto_id AND p.idcliente = f.idcliente
            WHERE {where}
            GROUP BY p.code, p.name
        """)
        detalle = dict(db.session.execute(sql_totales, params).mappings().first() or {})

        # --- Histórico mensual ---
        sql_hist = text(f"""
            SELECT DATE_TRUNC('month', f.fecha) AS mes,
                SUM(i.cantidad) AS cantidad,
                SUM(i.total_item) AS total
            FROM siigo_factura_items i
            JOIN facturas_enriquecidas f ON f.factura_id = i.factura_id
            WHERE {where}
            GROUP BY DATE_TRUNC('month', f.fecha)
            ORDER BY mes
        """)
        historico = [dict(r) for r in db.session.execute(sql_hist, params).mappings().all()]

        detalle["historico"] = historico
        return jsonify(detalle)




    # Endpoint de balance inicial:
    @app.route("/siigo/test-balance-report", methods=["GET"])
    def siigo_test_balance_report():
        """
        Endpoint para generar y obtener el enlace de descarga del Balance de Prueba General desde Siigo.
        Ejemplo:
        /siigo/test-balance-report?idcliente=1&year=2025&month_start=1&month_end=12
        """
        import requests

        idcliente = request.args.get("idcliente", type=int)
        year = request.args.get("year", type=int, default=2025)
        month_start = request.args.get("month_start", type=int, default=1)
        month_end = request.args.get("month_end", type=int, default=12)
        include_tax_diff = request.args.get("include_tax_diff", type=lambda v: v.lower() == "true", default=False)

        # Validación básica
        if not idcliente:
            return jsonify({"error": "Falta idcliente (ej: /siigo/test-balance-report?idcliente=1)"}), 400

        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        auth_data = _siigo_auth_json_for_client(cfg)
        if not isinstance(auth_data, dict):
            return jsonify({"error": "Auth inesperado", "detalle": str(auth_data)}), 500

        token = auth_data.get("access_token")
        if not token:
            return jsonify({"error": "No se obtuvo access_token", "detalle": auth_data}), 500

        base_url = cfg.base_url.rstrip("/")
        headers = _siigo_headers_bearer(token)

        # 🔧 Payload: dejamos account_start y account_end vacíos según la documentación
        payload = {
            "account_start": "",
            "account_end": "",
            "year": year,
            "month_start": month_start,
            "month_end": month_end,
            "includes_tax_difference": include_tax_diff,
        }

        url = f"{base_url}/v1/test-balance-report"

        try:
            r = requests.post(url, json=payload, headers=headers, timeout=120)
        except Exception as e:
            return jsonify({"error": "Error de conexión con Siigo", "detalle": str(e)}), 500

        status = r.status_code
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}

        if status in (200, 201) and "file_url" in data:
            return jsonify({
                "mensaje": "Balance generado exitosamente",
                "status": status,
                "file_id": data.get("file_id"),
                "file_url": data.get("file_url"),
                "payload_enviado": payload
            }), 200

        return jsonify({
            "error": "Fallo al generar el balance",
            "status": status,
            "respuesta": data,
            "payload_enviado": payload
        }), status



    # --- Generar link de descarga Balance de Prueba (JWT protegido) ---
    @app.route("/siigo/balance/generar", methods=["POST"])
    @jwt_required()
    def siigo_generar_balance():
        """
        Genera el link de descarga del Balance de Prueba General desde Siigo.
        Se usa dentro del frontend del módulo Balance de Prueba.

        Body esperado (JSON o FormData):
        {
            "year": 2025,
            "month_start": 1,
            "month_end": 12,
            "includes_tax_difference": false
        }
        """
        import requests

        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente asociado"}), 400

        # --- Leer parámetros ---
        data = request.get_json(silent=True) or request.form or {}
        year = int(data.get("year", 2025))
        month_start = int(data.get("month_start", 1))
        month_end = int(data.get("month_end", 12))
        include_tax_diff = bool(data.get("includes_tax_difference", False))

        # --- Obtener credenciales Siigo del cliente ---
        cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
        if not cfg:
            return jsonify({"error": "Credenciales Siigo no configuradas"}), 400

        auth_data = _siigo_auth_json_for_client(cfg)
        if not isinstance(auth_data, dict):
            return jsonify({"error": "Auth inesperado", "detalle": str(auth_data)}), 500

        token = auth_data.get("access_token")
        if not token:
            return jsonify({"error": "No se obtuvo access_token", "detalle": auth_data}), 500

        base_url = cfg.base_url.rstrip("/")
        headers = _siigo_headers_bearer(token)

        # --- Payload de la petición ---
        payload = {
            "account_start": "",
            "account_end": "",
            "year": year,
            "month_start": month_start,
            "month_end": month_end,
            "includes_tax_difference": include_tax_diff,
        }

        url = f"{base_url}/v1/test-balance-report"

        try:
            r = requests.post(url, json=payload, headers=headers, timeout=120)
        except Exception as e:
            return jsonify({"error": "Error de conexión con Siigo", "detalle": str(e)}), 500

        status = r.status_code
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}

        # --- Éxito ---
        if status in (200, 201) and "file_url" in data:
            return jsonify({
                "mensaje": "Balance generado exitosamente",
                "status": status,
                "file_id": data.get("file_id"),
                "file_url": data.get("file_url"),
                "payload_enviado": payload
            }), 200

        # --- Error ---
        return jsonify({
            "error": "Fallo al generar el balance",
            "status": status,
            "respuesta": data,
            "payload_enviado": payload
        }), status





    #Balance de PRUEBA
    # --- Importar Balance de Prueba desde Archivo Excel ---
    @app.route("/importar/balance-excel", methods=["POST"])
    @jwt_required()
    def importar_balance_desde_excel():
        import pandas as pd
        from datetime import datetime, timezone

        claims = get_jwt()
        idcliente = claims.get("idcliente")
        if not idcliente:
            return jsonify({"error": "Token sin cliente asociado"}), 400

        # Validar archivo
        if "archivo" not in request.files:
            return jsonify({"error": "Archivo no proporcionado"}), 400
        file = request.files["archivo"]

        # Leer parámetros de periodo
        anio = request.form.get("anio")
        mes_inicio = request.form.get("mes_inicio")
        mes_fin = request.form.get("mes_fin")

        if not anio or not mes_inicio or not mes_fin:
            return jsonify({"error": "Debe indicar año, mes de inicio y mes de fin"}), 400

        try:
            anio = int(anio)
            mes_inicio = int(mes_inicio)
            mes_fin = int(mes_fin)
        except ValueError:
            return jsonify({"error": "Mes o año inválido"}), 400

        # Leer archivo Excel con pandas y calamine
        try:
            df = pd.read_excel(file, header=4, engine="calamine")  # encabezado en fila 5
            df = df.dropna(how="all")  # eliminar filas vacías
            df = df.where(pd.notnull(df), None)
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({"error": f"No se pudo leer el Excel: {str(e)}"}), 400

        # Verificar columnas esperadas
        columnas_esperadas = [
            "Nivel",
            "Transaccional",
            "Código cuenta contable",
            "Nombre Cuenta contable",
            "Saldo Inicial",
            "Movimiento Débito",
            "Movimiento Crédito",
            "Saldo final",
        ]
        faltantes = [c for c in columnas_esperadas if c not in df.columns]
        if faltantes:
            return jsonify({"error": f"Faltan columnas esperadas: {faltantes}"}), 400

        # Eliminar registros anteriores
        try:
            BalancePrueba.query.filter_by(
                idcliente=idcliente,
                periodo_anio=anio,
                periodo_mes_inicio=mes_inicio,
                periodo_mes_fin=mes_fin
            ).delete()
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": f"Error al limpiar balances previos: {str(e)}"}), 500

        registros_creados = 0
        errores = []

        niveles_validos = {"Clase", "Grupo", "Cuenta", "Subcuenta", "Auxiliar", "Subauxiliar"}

        # Insertar cada fila
        for idx, row in df.iterrows():
            try:
                nivel = str(row.get("Nivel") or "").strip()
                if nivel not in niveles_validos:
                    continue  # ignorar filas inválidas

                registro = BalancePrueba(
                    idcliente=idcliente,
                    codigo_cuenta=str(row.get("Código cuenta contable") or "").strip(),
                    nombre_cuenta=str(row.get("Nombre Cuenta contable") or "").strip(),
                    nivel=nivel,
                    es_transaccional=str(row.get("Transaccional") or "").strip().lower() == "sí",
                    saldo_inicial=float(str(row.get("Saldo Inicial") or "0").replace(",", "").replace(" ", "")),
                    movimiento_debito=float(str(row.get("Movimiento Débito") or "0").replace(",", "").replace(" ", "")),
                    movimiento_credito=float(str(row.get("Movimiento Crédito") or "0").replace(",", "").replace(" ", "")),
                    saldo_final=float(str(row.get("Saldo final") or "0").replace(",", "").replace(" ", "")),
                    periodo_anio=anio,
                    periodo_mes_inicio=mes_inicio,
                    periodo_mes_fin=mes_fin,
                    fecha_carga=datetime.now(timezone.utc)
                )
                db.session.add(registro)
                registros_creados += 1
            except Exception as e:
                errores.append(f"Fila {idx + 5}: {e}")

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": f"Error al guardar en BD: {str(e)}"}), 500

        return jsonify({
            "mensaje": f"Balance {anio} ({mes_inicio} → {mes_fin}) importado correctamente.",
            "registros_creados": registros_creados,
            "errores_preview": errores[:5]
        }), 200


    # Endpoint que analisa el balance por clases
    # Endpoint que analiza el balance por clases contables (alineado con indicadores)
    @app.route("/reportes/balance/clases", methods=["GET"])
    @jwt_required()
    def resumen_por_clase_contable():
        idcliente = get_jwt().get("idcliente")
        anio = request.args.get("anio", type=int)
        mes_inicio = request.args.get("mes_inicio", type=int)
        mes_fin = request.args.get("mes_fin", type=int)

        if not idcliente or not anio or not mes_inicio or not mes_fin:
            return jsonify({"error": "Faltan parámetros"}), 400

        registros = db.session.query(
            BalancePrueba.codigo_cuenta,
            BalancePrueba.saldo_final
        ).filter(
            BalancePrueba.idcliente == idcliente,
            BalancePrueba.periodo_anio == anio,
            BalancePrueba.periodo_mes_inicio == mes_inicio,
            BalancePrueba.periodo_mes_fin == mes_fin,
            BalancePrueba.es_transaccional == True
        ).all()

        # Mapeo de clases por prefijo
        clases = {
            "Activo": ["1"],
            "Pasivo": ["2"],
            "Patrimonio": ["3"],
            "Ingresos": ["41", "42"],
            "Costos": ["61"],
            "Gastos": ["51", "53"]
        }

        resumen_map = {
            "Activo": 0,
            "Pasivo": 0,
            "Patrimonio": 0,
            "Ingresos": 0,
            "Costos": 0,
            "Gastos": 0
        }

        for cod, saldo in registros:
            cod_str = str(cod).strip()
            for clase, prefijos in clases.items():
                if any(cod_str.startswith(pref) for pref in prefijos):
                    resumen_map[clase] += float(saldo or 0)
                    break

        # Para coherencia visual en el gráfico
        ingresos = abs(resumen_map["Ingresos"])
        costos = abs(resumen_map["Costos"])
        gastos = abs(resumen_map["Gastos"])
        resultado_neto = ingresos - costos - gastos

        data = [
            {"clase": "Ingresos", "valor": ingresos},
            {"clase": "Costos", "valor": costos},
            {"clase": "Gastos", "valor": gastos},
            {"clase": "Resultado Neto (Utilidad o Pérdida)", "valor": resultado_neto},
            {"clase": "Activo", "valor": resumen_map["Activo"]},
            {"clase": "Pasivo", "valor": resumen_map["Pasivo"]},
            {"clase": "Patrimonio", "valor": resumen_map["Patrimonio"]},
        ]

        return jsonify({"resumen": data})





    @app.route("/reportes/balance/resumen", methods=["GET"])
    @jwt_required()
    def resumen_balance():
        idcliente = get_jwt().get("idcliente")
        anio = request.args.get("anio", type=int)
        mes_inicio = request.args.get("mes_inicio", type=int)
        mes_fin = request.args.get("mes_fin", type=int)

        if not idcliente or not anio:
            return jsonify({"error": "Faltan parámetros"}), 400

        q = db.session.query(
            BalancePrueba.nivel.label("clase"),
            db.func.sum(BalancePrueba.saldo_final).label("saldo_final")
        ).filter_by(
            idcliente=idcliente,
            periodo_anio=anio,
            periodo_mes_inicio=mes_inicio,
            periodo_mes_fin=mes_fin
        ).group_by(BalancePrueba.nivel).all()

        resumen = [
            {"clase": r.clase, "saldo_final": float(r.saldo_final or 0)}
            for r in q if (r.saldo_final or 0) != 0
        ]

        print("Resumen generado:", resumen)
        return jsonify({"resumen": resumen})


    # PAra analisis del balance por grupos contables
    @app.route("/reportes/balance/grupos", methods=["GET"])
    @jwt_required()
    def resumen_por_grupo_contable():
        idcliente = get_jwt().get("idcliente")
        anio = request.args.get("anio", type=int)
        mes_inicio = request.args.get("mes_inicio", type=int)
        mes_fin = request.args.get("mes_fin", type=int)

        if not idcliente or not anio or not mes_inicio or not mes_fin:
            return jsonify({"error": "Faltan parámetros"}), 400

         # --- 1️⃣ Obtener registros del balance de prueba ---
        registros = db.session.query(
            BalancePrueba.codigo_cuenta,
            BalancePrueba.nombre_cuenta,
            BalancePrueba.saldo_final
        ).filter(
            BalancePrueba.idcliente == idcliente,
            BalancePrueba.periodo_anio == anio,
            BalancePrueba.periodo_mes_inicio == mes_inicio,
            BalancePrueba.periodo_mes_fin == mes_fin,
            BalancePrueba.es_transaccional == True
        ).all()

        # Agrupaciones por prefijo de código
        grupos = {
            "Activo Corriente": ["11", "13"],
            "Activo No Corriente": ["15", "17"],
            "Pasivo a Corto Plazo": ["21", "22"],
            "Pasivo a Largo Plazo": ["23", "24", "25"],
            "Ingresos": ["41", "42"],
            "Costos": ["61"],
            "Gastos": ["51", "53"],
            "Patrimonio": ["3"],
            "Pasivo Total": ["2"],  # Nuevo grupo adicional si se requiere
        }


        resumen = []
        detalle = []

        for grupo, prefijos in grupos.items():
            total = 0
            cuentas = []

            for codigo, nombre, saldo in registros:
                codigo_str = str(codigo)
                if any(codigo_str.startswith(pref) for pref in prefijos):
                    total += saldo or 0
                    cuentas.append({
                        "codigo": codigo,
                        "nombre": nombre,
                        "valor": saldo or 0
                    })

            if cuentas:
                resumen.append({"grupo": grupo, "valor": total})
                detalle.append({"grupo": grupo, "cuentas": cuentas})

        def safe_val(grupo):
            """Devuelve el valor del grupo o 0 si no existe."""
            return next((item["valor"] for item in resumen if item["grupo"] == grupo), 0)

        # --- 3️⃣ Variables base coherentes con visión gerencial ---
        activo_corriente = safe_val("Activo Corriente")
        activo_no_corriente = safe_val("Activo No Corriente")
        pasivo_corto = abs(safe_val("Pasivo a Corto Plazo"))
        pasivo_largo = abs(safe_val("Pasivo a Largo Plazo"))
        ingresos = abs(safe_val("Ingresos"))  # 🔹 Ingresos siempre positivos
        costos = abs(safe_val("Costos"))      # 🔹 Costos siempre positivos
        gastos = abs(safe_val("Gastos"))      # 🔹 Gastos siempre positivos

        activo_total = activo_corriente + activo_no_corriente
        pasivo_total = pasivo_corto + pasivo_largo
        utilidad_neta = ingresos - costos - gastos

        # --- 4️⃣ Indicadores financieros consistentes ---
        indicadores = {
            "liquidez": round(activo_corriente / pasivo_corto, 2) if pasivo_corto else None,
            "apalancamiento": round(pasivo_total / activo_total, 2) if activo_total else None,
            "rentabilidad": round(utilidad_neta / ingresos, 2) if ingresos else None
        }

        # --- 5️⃣ Conclusiones automáticas coherentes ---
        conclusiones = []


        # Liquidez
        if indicadores["liquidez"] is not None:
            if indicadores["liquidez"] < 1:
                conclusiones.append("🚨 La empresa podría tener problemas de liquidez (activo corriente < pasivo corto plazo).")
            else:
                conclusiones.append("✅ Buena liquidez: el activo corriente cubre las obligaciones de corto plazo.")

        # Apalancamiento
        if indicadores["apalancamiento"] is not None:
            if indicadores["apalancamiento"] > 0.6:
                conclusiones.append("⚠ Alto nivel de endeudamiento. Evalúa reducir pasivos.")
            else:
                conclusiones.append("✅ Apalancamiento controlado.")

        # Rentabilidad
        if indicadores["rentabilidad"] is not None:
            if indicadores["rentabilidad"] < 0:
                conclusiones.append("🔻 Rentabilidad negativa: la empresa tuvo pérdidas netas.")
            elif indicadores["rentabilidad"] < 0.1:
                conclusiones.append("⚠ Rentabilidad positiva pero baja.")
            else:
                conclusiones.append("✅ Buena rentabilidad sobre ingresos.")

        # --- 6️⃣ Agregar resultado neto al resumen (antes del return)
        resumen.append({
            "grupo": "Resultado Neto (Utilidad o Pérdida)",
            "valor": utilidad_neta
        })

        # --- 7️⃣ Respuesta final
        return jsonify({
            "resumen": resumen,
            "detalle": detalle,
            "indicadores": indicadores,
            "conclusiones": conclusiones
        })





    # ================================================
    # 📊 Indicadores Financieros con Diagnóstico Ejecutivo
    # ================================================

    # Para reporte de Indicadores Financieros
    @app.route("/reportes/indicadores/financieros", methods=["GET"])
    @jwt_required()
    def indicadores_financieros():
        idcliente = get_jwt().get("idcliente")
        anio = request.args.get("anio", type=int)
        mes_inicio = request.args.get("mes_inicio", type=int)
        mes_fin = request.args.get("mes_fin", type=int)

        if not idcliente or not anio or not mes_inicio or not mes_fin:
            return jsonify({"error": "Faltan parámetros"}), 400

        registros = db.session.query(
            BalancePrueba.codigo_cuenta,
            BalancePrueba.nombre_cuenta,
            BalancePrueba.saldo_final
        ).filter(
            BalancePrueba.idcliente == idcliente,
            BalancePrueba.periodo_anio == anio,
            BalancePrueba.periodo_mes_inicio == mes_inicio,
            BalancePrueba.periodo_mes_fin == mes_fin,
            BalancePrueba.es_transaccional == True
        ).all()

        # Mapeo de grupos por prefijo
        grupos = {
            "Activo Corriente": ["11", "13"],
            "Activo No Corriente": ["15", "17"],
            "Pasivo a Corto Plazo": ["21", "22"],
            "Pasivo a Largo Plazo": ["23", "24", "25"],
            "Ingresos": ["41", "42"],
            "Costos": ["61"],
            "Gastos": ["51", "53"],
            "Patrimonio": ["3"],
        }

        # Sumas por grupo
        resumen_map = {}
        for grupo, prefijos in grupos.items():
            total = 0
            for codigo, _, saldo in registros:
                if any(str(codigo).startswith(pref) for pref in prefijos):
                    total += float(saldo or 0)
            resumen_map[grupo] = total

        # Variables base (signos coherentes para cálculo)
        activo_corriente = float(resumen_map.get("Activo Corriente", 0))
        activo_no_corriente = float(resumen_map.get("Activo No Corriente", 0))
        pasivo_corto = abs(float(resumen_map.get("Pasivo a Corto Plazo", 0)))
        pasivo_largo = abs(float(resumen_map.get("Pasivo a Largo Plazo", 0)))
        pasivo_total_real = sum(
            float(saldo or 0)
            for codigo, _, saldo in registros
            if str(codigo).startswith("2")
        )
        ingresos = abs(float(resumen_map.get("Ingresos", 0)))
        costos = abs(float(resumen_map.get("Costos", 0)))
        gastos = abs(float(resumen_map.get("Gastos", 0)))
        patrimonio = float(resumen_map.get("Patrimonio", 0))

        activo_total = activo_corriente + activo_no_corriente
        pasivo_total = abs(pasivo_total_real)
        utilidad_neta = ingresos - costos - gastos

        # Indicadores
        indicadores = {
            "liquidez": round(activo_corriente / pasivo_corto, 2) if pasivo_corto else None,
            "apalancamiento": round(pasivo_total / activo_total, 2) if activo_total else None,
            "rentabilidad": round(utilidad_neta / ingresos, 2) if ingresos else None,
            "capital_trabajo": round(activo_corriente - pasivo_corto, 2),
            "solvencia": round(activo_total / pasivo_total, 2) if pasivo_total else None,
            "autonomia": round(patrimonio / activo_total, 2) if activo_total else None,
            "porcentaje_pasivo_corto": round(pasivo_corto / pasivo_total, 2) if pasivo_total else None,
            "porcentaje_activo_no_corriente": round(activo_no_corriente / activo_total, 2) if activo_total else None,
            "cobertura_activo_pasivo": round(activo_total / pasivo_total, 2) if pasivo_total else None,
            # Solo si patrimonio > 0, de lo contrario no interpretable
            "endeudamiento_largo_plazo": round(pasivo_largo / patrimonio, 2) if patrimonio and patrimonio > 0 else None,
            # Para poder armar el resumen técnico en el front si lo requieren
            "activo_total": round(activo_total, 2),
            "pasivo_total": round(pasivo_total, 2),
            "patrimonio": round(patrimonio, 2),
            "ingresos": round(ingresos, 2),
            "costos": round(costos, 2),
            "gastos": round(gastos, 2),
            "utilidad_neta": round(utilidad_neta, 2),
        }

        # Interpretaciones dinámicas para cada indicador
        interpretaciones = {
            k: interpretar_indicador(k, v)
            for k, v in indicadores.items()
        }

        # Explicaciones breves por indicador (tooltip/tarjetas)
        explicaciones = {
            "liquidez": "Activo corriente / Pasivo a corto. >1 saludable; >2 holgado.",
            "apalancamiento": "Pasivo total / Activo total. <0.6 ideal; >0.8 alto.",
            "rentabilidad": "Utilidad neta / Ingresos. >0 indica margen neto positivo.",
            "capital_trabajo": "Activo corriente − Pasivo corto. >0 indica colchón operativo.",
            "solvencia": "Activo total / Pasivo total. >1 indica cobertura de deudas.",
            "autonomia": "Patrimonio / Activo total. >0.5 indica menor dependencia de deuda.",
            "porcentaje_pasivo_corto": "Proporción de deuda exigible pronto.",
            "porcentaje_activo_no_corriente": "Proporción de activos no líquidos.",
            "cobertura_activo_pasivo": "Cobertura de pasivos con activos.",
            "endeudamiento_largo_plazo": "Deuda estructural vs patrimonio (si patrimonio > 0).",
        }

        # Resumen técnico gerencial (valores positivos para claridad)
        resumen_financiero = [
            {"clase": "Activo total", "valor": float(activo_total), "interpretacion": "Total de activos."},
            {"clase": "Pasivo total", "valor": float(pasivo_total), "interpretacion": "Deuda total acumulada."},
            {"clase": "Patrimonio", "valor": float(patrimonio), "interpretacion": "Capital propio neto (puede ser negativo)."},
            {"clase": "Ingresos", "valor": float(ingresos), "interpretacion": "Ventas totales del período."},
            {"clase": "Costos", "valor": float(costos), "interpretacion": "Costo directo de operaciones."},
            {"clase": "Gastos", "valor": float(gastos), "interpretacion": "Gasto operativo y administrativo."},
            {"clase": "Utilidad neta", "valor": float(utilidad_neta), "interpretacion": "Resultado neto del período."},
        ]

        # Conclusiones automáticas
        conclusiones = []
        if indicadores["liquidez"] is not None:
            if indicadores["liquidez"] < 1:
                conclusiones.append("⚠ Riesgo de iliquidez: el activo corriente no cubre el pasivo a corto.")
            elif indicadores["liquidez"] > 3:
                conclusiones.append("⚠ Exceso de liquidez: posible ineficiencia en el uso del capital disponible.")
            else:
                conclusiones.append("✅ Liquidez saludable para cubrir obligaciones de corto plazo.")
        if indicadores["apalancamiento"] is not None:
            if indicadores["apalancamiento"] > 0.8:
                conclusiones.append("⚠ Apalancamiento alto: gran parte de los activos están financiados con deuda.")
            elif indicadores["apalancamiento"] > 0.6:
                conclusiones.append("• Apalancamiento moderado: monitorear endeudamiento.")
            else:
                conclusiones.append("✅ Estructura de capital sana (endeudamiento controlado).")
        if indicadores["rentabilidad"] is not None:
            if indicadores["rentabilidad"] < 0:
                conclusiones.append("🔻 Rentabilidad negativa: la empresa ha tenido pérdidas netas en el período.")
            elif indicadores["rentabilidad"] < 0.1:
                conclusiones.append("• Rentabilidad positiva pero baja: revisar eficiencia operativa.")
            else:
                conclusiones.append("✅ Buen margen neto sobre ingresos.")
        if indicadores["autonomia"] is not None and indicadores["autonomia"] < 0.3:
            conclusiones.append("⚠ Alta dependencia del financiamiento externo (autonomía < 30%).")
        if patrimonio <= 0:
            conclusiones.append("❗ Patrimonio negativo o nulo: la empresa presenta pérdida acumulada superior a su capital.")
        elif indicadores["endeudamiento_largo_plazo"] is not None and indicadores["endeudamiento_largo_plazo"] > 1:
            conclusiones.append("⚠ Endeudamiento estructural alto respecto al patrimonio.")

        return jsonify({
            "resumen_financiero": resumen_financiero,
            "indicadores": indicadores,
            "explicaciones": explicaciones,
            "interpretaciones": interpretaciones,
            "conclusiones": conclusiones
        })


    # Reporte Criuce de IVAs
    @app.route("/reportes/cruce_iva", methods=["GET"])
    @jwt_required()
    def get_cruce_iva():
        claims = get_jwt()
        perfilid = claims.get("perfilid")
        idcliente = claims.get("idcliente")

        q_idcliente = request.args.get("idcliente", type=int)
        if perfilid == 0 and q_idcliente:
            idcliente = q_idcliente

        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        desde_str = request.args.get("desde")
        hasta_str = request.args.get("hasta")
        modo = request.args.get("modo", "mensual").lower()
        incluir_detalle = request.args.get("detalle", "0") == "1"

        modos_validos = {
            "mensual": 1,
            "bimensual": 2,
            "trimestral": 3,
            "cuatrimestral": 4
        }
        agrupacion_meses = modos_validos.get(modo, 1)

        try:
            desde = datetime.strptime(desde_str, "%Y-%m-%d") if desde_str else None
            hasta = datetime.strptime(hasta_str, "%Y-%m-%d") if hasta_str else None
        except:
            return jsonify({"error": "Formato de fecha inválido. Usa YYYY-MM-DD"}), 400

        params = {"idcliente": idcliente}
        wh_ventas = ["f.idcliente = :idcliente"]
        wh_compras = ["c.idcliente = :idcliente"]
        filtro_nc_fecha = []

        if desde:
            wh_ventas.append("f.fecha >= :desde")
            wh_compras.append("c.fecha >= :desde")
            filtro_nc_fecha.append("nc.fecha >= :desde")
            params["desde"] = desde
        if hasta:
            wh_ventas.append("f.fecha <= :hasta")
            wh_compras.append("c.fecha <= :hasta")
            filtro_nc_fecha.append("nc.fecha <= :hasta")
            params["hasta"] = hasta

        sql_main = text(f"""
            WITH notas_credito_ajuste AS (
                SELECT
                    EXTRACT(YEAR FROM nc.fecha) AS anio,
                    EXTRACT(MONTH FROM nc.fecha) AS mes,
                    SUM(
                        CASE 
                            WHEN f.total IS NOT NULL AND nc.total >= 0.9 * f.total THEN f.impuestos_total
                            ELSE (f.impuestos_total * (nc.total / f.total))
                        END
                    ) AS iva_nc
                FROM siigo_notas_credito nc
                LEFT JOIN facturas_enriquecidas f 
                    ON nc.factura_afectada_id = f.idfactura
                WHERE nc.idcliente = :idcliente
                {f" AND {' AND '.join(filtro_nc_fecha)}" if filtro_nc_fecha else ""}
                GROUP BY anio, mes
            ),
            ventas AS (
                SELECT
                    EXTRACT(YEAR FROM f.fecha) AS anio,
                    EXTRACT(MONTH FROM f.fecha) AS mes,
                    SUM(f.impuestos_total) - COALESCE(nc.iva_nc, 0) AS iva_ventas
                FROM facturas_enriquecidas f
                LEFT JOIN notas_credito_ajuste nc
                    ON EXTRACT(YEAR FROM f.fecha) = nc.anio AND EXTRACT(MONTH FROM f.fecha) = nc.mes
                WHERE {" AND ".join(wh_ventas)}
                GROUP BY EXTRACT(YEAR FROM f.fecha), EXTRACT(MONTH FROM f.fecha), nc.iva_nc
            ),
            compras AS (
                SELECT
                    EXTRACT(YEAR FROM c.fecha) AS anio,
                    EXTRACT(MONTH FROM c.fecha) AS mes,
                    SUM(ci.impuestos) AS iva_compras
                FROM siigo_compras_items ci
                JOIN siigo_compras c ON ci.compra_id = c.id
                WHERE {" AND ".join(wh_compras)}
                GROUP BY anio, mes
            ),
            combinadas AS (
                SELECT COALESCE(v.anio, c.anio) AS anio,
                    COALESCE(v.mes, c.mes) AS mes,
                    COALESCE(v.iva_ventas, 0) AS iva_ventas,
                    COALESCE(c.iva_compras, 0) AS iva_compras,
                    COALESCE(v.iva_ventas, 0) - COALESCE(c.iva_compras, 0) AS saldo_iva
                FROM ventas v
                FULL OUTER JOIN compras c
                ON v.anio = c.anio AND v.mes = c.mes
            )
            SELECT anio,
                mes,
                TO_CHAR(MAKE_DATE(anio::int, mes::int, 1), 'YYYY-MM') AS periodo,
                TO_CHAR(MAKE_DATE(anio::int, mes::int, 1) + INTERVAL '1 month', 'YYYY-MM') AS mes_presentacion,
                SUM(iva_ventas) AS iva_ventas,
                SUM(iva_compras) AS iva_compras,
                SUM(saldo_iva) AS saldo_iva
            FROM combinadas
            GROUP BY anio, mes
            ORDER BY anio, mes
        """)

        try:
            result = db.session.execute(sql_main, params).mappings().all()
            rows = [dict(r) for r in result]

            kpis = {
                "iva_ventas": sum(r["iva_ventas"] for r in rows),
                "iva_compras": sum(r["iva_compras"] for r in rows),
                "saldo_iva": sum(r["saldo_iva"] for r in rows),
            }

            series = [
                {
                    "label": r["periodo"],
                    "mes_presentacion": r["mes_presentacion"],
                    "iva_ventas": r["iva_ventas"],
                    "iva_compras": r["iva_compras"],
                    "saldo_iva": r["saldo_iva"],
                }
                for r in rows
            ]

            def agrupar(rows, step):
                grupos = []
                for i in range(0, len(rows), step):
                    grupo = rows[i:i+step]
                    if not grupo:
                        continue
                    iva_ventas = sum(r["iva_ventas"] or 0 for r in grupo)
                    iva_compras = sum(r["iva_compras"] or 0 for r in grupo)
                    saldo_iva = sum(r["saldo_iva"] or 0 for r in grupo)

                    grupos.append({
                        "label": " + ".join(r["periodo"] for r in grupo),
                        "mes_presentacion": grupo[-1]["mes_presentacion"],
                        "iva_ventas": iva_ventas,
                        "iva_compras": iva_compras,
                        "saldo_iva": saldo_iva,
                    })

                # 👉 Aplicar lógica de arrastre
                saldo_acumulado = 0
                for g in grupos:
                    g["arrastre_anterior"] = saldo_acumulado
                    neto = g["saldo_iva"] + saldo_acumulado
                    g["iva_neto_a_pagar"] = max(neto, 0)
                    saldo_acumulado = neto if neto < 0 else 0

                return grupos

            series_agrupadas = {
                "bimensual": agrupar(rows, 2),
                "trimestral": agrupar(rows, 3),
                "cuatrimestral": agrupar(rows, 4),
            }

            response = {
                "rows": rows,
                "series": series,
                "series_agrupadas": series_agrupadas,
                "kpis": kpis,
                "modo": modo,
                "count": len(rows),
            }

            if incluir_detalle:
                detalle_ventas = db.session.execute(text(f"""
                    SELECT TO_CHAR(DATE_TRUNC('month', fecha), 'YYYY-MM') AS periodo,
                        idfactura, fecha, cliente_nombre,
                        impuestos_total, total, public_url
                    FROM facturas_enriquecidas f
                    WHERE {" AND ".join(wh_ventas)}
                    ORDER BY fecha
                """), params).mappings().all()

                detalle_compras = db.session.execute(text(f"""
                    SELECT TO_CHAR(DATE_TRUNC('month', c.fecha), 'YYYY-MM') AS periodo,
                        c.idcompra, c.fecha, c.proveedor_nombre,
                        SUM(ci.impuestos) AS impuestos_total,
                        c.total, c.factura_proveedor
                    FROM siigo_compras_items ci
                    JOIN siigo_compras c ON ci.compra_id = c.id
                    WHERE {" AND ".join(wh_compras)}
                    GROUP BY c.idcompra, c.fecha, c.proveedor_nombre, c.total, c.factura_proveedor
                    ORDER BY c.fecha
                """), params).mappings().all()

                def agrupar_facturas(filas):
                    agrupado = {}
                    for f in filas:
                        p = f["periodo"]
                        agrupado.setdefault(p, []).append(dict(f))
                    return agrupado

                response["facturas_ventas"] = agrupar_facturas(detalle_ventas)
                response["facturas_compras"] = agrupar_facturas(detalle_compras)

            return jsonify(response)

        except Exception as e:
            return jsonify({"error": str(e)}), 500







    # --- Registrar rutas de permisos ---
    from permisos_routes import register_permisos_routes
    register_permisos_routes(app)


    @app.before_request
    def verificar_permisos_global():
        # 🔓 Excepciones (rutas públicas o de login)
        if request.method == "OPTIONS":
            return jsonify({"status": "ok"}), 200  # ← ✅ soluciona preflight correctamente

        if request.path.startswith("/auth") or request.path == "/":
            return

        # ⚠️ Excluir rutas internas que se llaman desde /siigo/sync-all
        rutas_exentas = [
            "/siigo/sync-catalogos",
            "/siigo/sync-customers",
            "/siigo/sync-proveedores",
            "/siigo/sync-productos",
            "/siigo/sync-facturas",
            "/siigo/sync-notas-credito",
            "/siigo/sync-compras",
            "/siigo/sync-accounts-payable",
            "/siigo/cross-accounts-payable",
            "/siigo/sync-all",
            "/config/siigo-sync-status", 
            "/ping",  # 👈 AGREGA ESTA LÍNEA PARA EL PING
        ]
        for ruta in rutas_exentas:
            if ruta in request.path:
                return


        # ✅ Verifica JWT válido
        try:
            verify_jwt_in_request(optional=False)
        except Exception as e:
            return jsonify({"error": f"Token inválido o faltante: {str(e)}"}), 401

        claims = get_jwt()

        if _is_superadmin(claims):
            return  # 👑 SuperAdmin entra sin restricciones

        idperfil = claims.get("perfilid")
        idcliente = claims.get("idcliente")

        # 🧠 Debug temporal
        print(f"[PERMISOS] Ruta: {request.path}, Método: {request.method}, Perfil: {idperfil}, Cliente: {idcliente}")

        # 🔹 Reglas automáticas por prefijo de ruta
        codigo = None

        if request.path.startswith("/clientes"):
            codigo = "ver_clientes"

        elif request.path.startswith("/siigo"):
            codigo = "ver_siigo"

        elif request.path.startswith("/admin"):
            codigo = "admin_panel"

        elif request.path.startswith("/reportes"):
            # Detectar permisos específicos
            if "compras-gastos" in request.path:
                codigo = "ver_reporte_compras_gastos"
            elif "indicadores" in request.path:
                codigo = "ver_reporte_indicadores"
            elif "ventas" in request.path:
                codigo = "ver_reporte_ventas"
            elif "balance" in request.path:
                codigo = "ver_reporte_balance"
            elif "consolidado" in request.path:
                codigo = "ver_reporte_consolidado"
            elif "clientes" in request.path:
                codigo = "ver_reporte_clientes"
            elif "proveedores" in request.path:
                codigo = "ver_reporte_proveedores"
            elif "productos" in request.path:
                codigo = "ver_reporte_productos"
            elif "nomina" in request.path:
                codigo = "ver_reporte_nomina"
            elif "cxc" in request.path or "cartera" in request.path:
                codigo = "ver_reporte_cxc"
            elif "cruce_iva" in request.path:
                codigo = "ver_reporte_cruceivas"
            else:
                # Si no se reconoce un reporte específico, usa permiso general
                codigo = "ver_reportes"

        # Si no hay permiso requerido, no aplica control
        if not codigo:
            return

        # 🔒 Verifica el permiso en BD
        if not _perfil_tiene_permiso(idperfil, idcliente, codigo):
            return jsonify({
                "error": f"Acceso denegado: falta permiso '{codigo}'",
                "ruta": request.path
            }), 403



    @app.route("/config/sync", methods=["GET", "OPTIONS"])
    @jwt_required()
    @cross_origin()
    def get_sync_config():
        idcliente = get_jwt().get("idcliente")
        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        config = SiigoSyncConfig.query.filter_by(idcliente=idcliente).first()
        return jsonify(config.as_dict()) if config else jsonify({})




    @app.route("/config/sync", methods=["POST", "OPTIONS"])
    @jwt_required()
    @cross_origin()
    def save_sync_config():
        idcliente = get_jwt().get("idcliente")
        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        data = request.get_json() or {}

        config = SiigoSyncConfig.query.filter_by(idcliente=idcliente).first()
        if not config:
            config = SiigoSyncConfig(idcliente=idcliente)
            db.session.add(config)

        config.hora_ejecucion = data["hora_ejecucion"]
        config.frecuencia_dias = data.get("frecuencia_dias", 1)
        config.activo = data.get("activo", True)

        db.session.commit()
        return jsonify({"mensaje": "Configuración guardada"}), 200


    
    @app.route("/config/siigo-sync-status", methods=["GET", "OPTIONS"]) 
    @jwt_required()
    @cross_origin()  # opcional si ya tienes CORS global
    def config_siigo_sync_status():
        idcliente = get_jwt().get("idcliente")
        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        config = SiigoSyncConfig.query.filter_by(idcliente=idcliente).first()
        if not config:
            return jsonify({
                "pendientes": 0,
                "ultimo_ejec": None,
                "resultado": None,
                "detalle": "",
                "hora_ejecucion": None,
                "frecuencia_dias": 1,
                "activo": False,
            })

        # 🔹 Obtener timezone del cliente (o Bogotá por defecto)
        cliente = Cliente.query.get(idcliente)
        tz_str = (cliente.timezone if cliente and cliente.timezone else "America/Bogota")

        # 🔹 Convertir de UTC (BD) → hora local del cliente
        if config.ultimo_ejecutado:
            dt_local = utc_to_local(config.ultimo_ejecutado, tz_str)
            ultimo_ejec = dt_local.isoformat()
        else:
            ultimo_ejec = None

        return jsonify({
            "pendientes": 0,
            "ultimo_ejec": ultimo_ejec,  # ← ya viene en hora local
            "resultado": config.resultado_ultima_sync,
            "detalle": config.detalle_ultima_sync or "",
            "hora_ejecucion": config.hora_ejecucion.strftime("%H:%M") if config.hora_ejecucion else None,
            "frecuencia_dias": config.frecuencia_dias,
            "activo": config.activo,
            "timezone": tz_str  # 👈 nuevo campo
        })




    # Enpoint para llevar a cabo la ejecucion del boton de sincronizacion de todo en siigo
    # Endpoint para sincronizar todo (invoca internamente otros endpoints)
    @app.route("/siigo/sync-all", methods=["POST"])
    def siigo_sync_all():
        idcliente = obtener_idcliente_desde_request()
        print(f"🔹 Sync-all iniciado para cliente {idcliente}")
        if not idcliente:
            return jsonify({"error": "Cliente no autorizado"}), 403

        data = request.get_json(silent=True) or {}
        origen = data.get("origen", "cron")
        es_manual = origen == "manual"

        log_parts = []
        overall_status = "OK"

        # 🕒 Obtener zona horaria del cliente
        cliente = Cliente.query.get_or_404(idcliente)
        tz_str = cliente.timezone or "America/Bogota"
        print(f"🌎 Zona horaria detectada para cliente {idcliente}: {tz_str}")

        # 🔁 Secuencia de endpoints Siigo a ejecutar
        sequence = [
            ("/siigo/sync-catalogos", {}),
            ("/siigo/sync-customers", {}),
            ("/siigo/sync-proveedores", {}),
            ("/siigo/sync-productos", {}),
            ("/siigo/sync-facturas", {}),
            ("/siigo/sync-facturas", {"deep": 1, "batch": 100, "only_missing": 1}),
            ("/siigo/sync-notas-credito", {}),
            ("/siigo/sync-compras", {}),
            ("/siigo/sync-accounts-payable", {}),
            ("/siigo/cross-accounts-payable", {}),
        ]

        print("🚀 === INICIO SECUENCIA SYNC-ALL ===")

        # 🧠 Ejecuta cada endpoint localmente (sin salir del proceso Flask)
        with app.test_client() as client:
            for ep, params in sequence:
                try:
                    print(f"➡️  Ejecutando {ep} ...")
                    inicio = time.time()

                    resp = client.post(
                        ep,
                        headers={
                            "X-ID-CLIENTE": str(idcliente),
                            "X-SYNC-ALL": "1"
                        },
                        query_string=params
                    )

                    dur = round(time.time() - inicio, 1)
                    print(f"✅ {ep} completado en {dur}s → {resp.status_code}")

                    status = resp.status_code
                    body = resp.get_data(as_text=True)
                    log_parts.append(f"{ep} {params} → {status}: {body}")

                    # 📊 Guardar métrica individual del endpoint
                    try:
                        resumen = body[:300] if body else None
                        metric = SiigoSyncMetric(
                            idcliente=idcliente,
                            endpoint=ep,
                            duracion_segundos=dur,
                            status_code=status,
                            resultado="OK" if status < 400 else "ERROR",
                            detalle_resumen=resumen
                        )
                        db.session.add(metric)
                        db.session.commit()
                    except Exception as e:
                        print(f"⚠️  Error guardando métrica: {e}")

                    if status >= 400:
                        overall_status = "ERROR"
                        break

                except Exception as e:
                    overall_status = "ERROR"
                    log_parts.append(f"{ep} excepción: {str(e)}")
                    break

        # 🟢 Consolidar logs finales
        detalle = "\n".join(log_parts)

        # ✅ Usar pytz solo localmente (sin afectar otras partes del programa)
        import pytz
        tz_obj = pytz.timezone(tz_str)
        now_local = datetime.now(tz_obj)
        print(f"🕒 Fecha/hora local: {now_local.isoformat()}")
        print(f"🕐 Offset local detectado: {now_local.utcoffset()}")
        print(f"📦 Guardando hora local con zona horaria incluida para cliente {idcliente}")

        # 🧩 Actualizar configuración o crearla
        config = SiigoSyncConfig.query.filter_by(idcliente=idcliente).first()
        if config:
            if es_manual:
                config.hora_ejecucion = now_local.time()
            config.ultimo_ejecutado = now_local  # ✅ Guardamos hora local con tzinfo
            config.resultado_ultima_sync = overall_status
            config.detalle_ultima_sync = detalle[:10000]
            db.session.add(config)
        else:
            hora = now_local.time() if es_manual else datetime.time(2, 0)
            config = SiigoSyncConfig(
                idcliente=idcliente,
                hora_ejecucion=hora,
                frecuencia_dias=1,
                activo=True,
                ultimo_ejecutado=now_local,
                resultado_ultima_sync=overall_status,
                detalle_ultima_sync=detalle[:10000],
            )
            db.session.add(config)

        # 🧾 Registrar log histórico (ya en hora local del cliente)
        logrec = SiigoSyncLog(
            idcliente=idcliente,
            fecha_programada=now_local,
            ejecutado_en=now_local,
            resultado=overall_status,
            detalle=detalle[:10000],
        )
        db.session.add(logrec)
        db.session.commit()

       # 🟢 Crear notificación para administradores del cliente
        try:
            titulo = "Sincronización automática completada"
            # Detectar el último endpoint fallido, si hubo error
            ep_fallido = None
            for line in reversed(log_parts):
                if "→" in line and "ERROR" in line or "excepción" in line:
                    ep_fallido = line.split(" ")[0]
                    break


            if overall_status == "OK":
                mensaje = f"✅ La sincronización automática de Siigo finalizó correctamente el {now_local.strftime('%d/%m/%Y %H:%M')} ({tz_str})."
                nivel = "success"
            else:
                mensaje = f"❌ La sincronización automática de Siigo falló en {ep_fallido or 'uno de los módulos'} el {now_local.strftime('%d/%m/%Y %H:%M')} ({tz_str}). Revisa los reportes de integración para más detalles."
                nivel = "error"

            notif = SystemNotification(
                idcliente=idcliente,
                tipo="SYNC_RESULT",
                titulo=titulo,
                mensaje=mensaje,
                nivel=nivel,
                leido=False
            )
            db.session.add(notif)
            db.session.commit()
            print(f"📢 Notificación creada para cliente {idcliente}: {nivel}")
        except Exception as e:
            print(f"⚠️ Error creando notificación: {e}")

        print("✅ Registro en BD completado. Verifica hora con offset correcto en logs/DB.\n")

        return jsonify({
            "status": overall_status,
            "detalle": detalle
        })



    # --- CRON: Verificador automático de sincronización Siigo (cada 4 horas) ---
    @app.route("/cron/siigo-verifier", methods=["GET"])
    def cron_siigo_verifier():
        """
        Verifica en siigo_sync_config qué clientes deben ejecutar sync-all
        en las próximas 4 horas (según su zona horaria y frecuencia).
        Ejecuta si están dentro del rango.
        """
        from datetime import datetime, timedelta
        import pytz

        print("⏰ CRON Siigo-verifier iniciado...")

        ahora_utc = datetime.utcnow().replace(tzinfo=pytz.utc)
        rango_horas = 4  # 🔹 Cada 4 horas
        print(f"🕓 Hora actual UTC: {ahora_utc.isoformat()}")

        # Buscar configuraciones activas
        configs = SiigoSyncConfig.query.filter_by(activo=True).all()
        if not configs:
            print("⚠️ No hay configuraciones activas en siigo_sync_config.")
            return jsonify({"mensaje": "Sin configuraciones activas"})

        ejecutados = []
        skip_por_frecuencia = []
        fuera_de_rango = []

        for cfg in configs:
            cliente = Cliente.query.get(cfg.idcliente)
            if not cliente:
                continue

            tz_str = cliente.timezone or "America/Bogota"
            tz_obj = pytz.timezone(tz_str)
            ahora_local = ahora_utc.astimezone(tz_obj)

            hora_prog = cfg.hora_ejecucion
            fecha_prog_local = datetime.combine(ahora_local.date(), hora_prog)
            fecha_prog_local = tz_obj.localize(fecha_prog_local)

            # Ajuste si ya pasó la hora programada hoy → usar la de mañana
            if fecha_prog_local < ahora_local:
                fecha_prog_local += timedelta(days=1)

            # Verificar frecuencia
            if cfg.ultimo_ejecutado:
                dias_desde_ultima = (ahora_utc - cfg.ultimo_ejecutado).days
                if dias_desde_ultima < cfg.frecuencia_dias:
                    skip_por_frecuencia.append(cliente.idcliente)
                    continue

            # Si está dentro de las próximas 4 horas, ejecutar
            diff_horas = (fecha_prog_local - ahora_local).total_seconds() / 3600
            if 0 <= diff_horas <= rango_horas:
                print(f"🚀 Ejecutando sync-all para cliente {cliente.idcliente} ({tz_str})")
                try:
                    with app.test_client() as client:
                        resp = client.post(
                            "/siigo/sync-all",
                            headers={"X-ID-CLIENTE": str(cliente.idcliente)},
                            json={"origen": "cron"}
                        )
                        print(f"✅ Cliente {cliente.idcliente} → {resp.status_code}")
                        ejecutados.append(cliente.idcliente)
                except Exception as e:
                    print(f"❌ Error en cliente {cliente.idcliente}: {e}")
            else:
                fuera_de_rango.append(cliente.idcliente)

        print(f"🟢 Ejecutados: {ejecutados}")
        print(f"⏸ Omitidos por frecuencia: {skip_por_frecuencia}")
        print(f"⏰ Fuera de rango horario: {fuera_de_rango}")

        return jsonify({
            "hora_utc": ahora_utc.isoformat(),
            "ejecutados": ejecutados,
            "omitidos_por_frecuencia": skip_por_frecuencia,
            "fuera_de_rango": fuera_de_rango,
            "total_activos": len(configs)
        })



    @app.route("/api/notificaciones", methods=["GET"])
    @jwt_required()
    def get_notificaciones():
        claims = get_jwt()
        idcliente = claims.get("idcliente")
        perfilid = claims.get("perfilid")

        if not idcliente:
            return jsonify({"error": "No autorizado"}), 403

        # Solo administradores del cliente o superadmin (perfilid == 0)
        if perfilid not in [0, 1]:
            return jsonify([])

        notifs = (
            SystemNotification.query
            .filter_by(idcliente=idcliente, leido=False)
            .order_by(SystemNotification.creado_en.desc())
            .limit(5)
            .all()
        )

        return jsonify([
            {
                "id": n.id,
                "titulo": n.titulo,
                "mensaje": n.mensaje,
                "nivel": n.nivel,
                "fecha": n.creado_en.isoformat()
            }
            for n in notifs
        ])



    @app.route("/api/notificaciones/marcar-leida/<int:notif_id>", methods=["POST"])
    @jwt_required()
    def marcar_notificacion_leida(notif_id):
        idcliente = get_jwt().get("idcliente")
        notif = SystemNotification.query.filter_by(id=notif_id, idcliente=idcliente).first()
        if notif:
            notif.leido = True
            db.session.commit()
        return jsonify({"ok": True})




    # Para verificar la conexion del BAckend
    @app.route("/ping")
    def ping():
        return {"message": "pong"}, 200



    return app

app = create_app()  # 👈 ESTA LÍNEA ES CLAVE PARA RAILWAY (Gunicorn la necesita)


if __name__ == "__main__":
    app.run(debug=True)

