# permisos_routes.py
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from sqlalchemy.exc import IntegrityError
from models import db, Usuario, Perfil, Permiso, PerfilPermiso
from decoradores_seguridad import _perfil_tiene_permiso

# -----------------------
# Helper functions
# -----------------------
def _is_superadmin(claims: dict) -> bool:
    return claims.get("perfilid") == 0  # ya existente


def _is_cliente_admin(claims: dict) -> bool:
    """
    Determina si el usuario autenticado tiene perfil de 'Administrador' dentro de su cliente.
    Se basa en la tabla perfiles.nombre == 'Administrador'
    """
    if _is_superadmin(claims):
        return True
    perfilid = claims.get("perfilid")
    if not perfilid:
        return False
    perfil = Perfil.query.filter_by(idperfil=perfilid).first()
    if perfil and perfil.nombre.lower() == "administrador":
        return True
    return False


def _get_request_idcliente_or_claims(claims: dict) -> int | None:
    if _is_superadmin(claims):
        q = request.args.get("idcliente", type=int)
        return q
    return claims.get("idcliente")

def _guard_tenant_access_or_403(claims: dict, target_idcliente: int | None):
    if _is_superadmin(claims):
        if target_idcliente is None:
            return jsonify({"error": "Falta idcliente (requerido para superadmin)"}), 400
        return None
    token_idcliente = claims.get("idcliente")
    if token_idcliente is None or token_idcliente != target_idcliente:
        return jsonify({"error": "Acceso denegado al tenant"}), 403
    return None

# -----------------------
# Registro de rutas
# -----------------------
def register_permisos_routes(app):

    # ====== Permisos del cliente ======
    @app.route("/api/permisos", methods=["GET"])
    @jwt_required()
    def list_permisos():
        claims = get_jwt()
        idcliente = _get_request_idcliente_or_claims(claims)
        err = _guard_tenant_access_or_403(claims, idcliente)
        if err:
            return err

        # 1️⃣ Buscar permisos propios del cliente
        permisos = Permiso.query.filter_by(idcliente=idcliente).order_by(Permiso.codigo.asc()).all()

        # 2️⃣ Si el cliente no tiene permisos, mostrar los permisos base del sistema (idcliente IS NULL)
        if not permisos:
            print(f"[PERMISOS] Cliente {idcliente} sin permisos → usando base global")
            permisos = Permiso.query.filter(Permiso.idcliente.is_(None)).order_by(Permiso.codigo.asc()).all()

            # Si ni siquiera hay globales, devolver error informativo
            if not permisos:
                return jsonify({
                    "error": "No hay permisos base definidos en el sistema. Un administrador debe crearlos."
                }), 404

        return jsonify([
            {
                "idpermiso": p.idpermiso,
                "nombre": p.nombre,
                "codigo": p.codigo,
                "descripcion": p.descripcion,
                "activo": p.activo,
                "idcliente": p.idcliente,
                "created_at": p.created_at.isoformat() if p.created_at else None
            } for p in permisos
        ])




    @app.route("/api/permisos", methods=["POST"])
    @jwt_required()
    def create_permiso():
        claims = get_jwt()

        # Solo superadmin o cliente administrador
        if not (_is_superadmin(claims) or _is_cliente_admin(claims)):
            return jsonify({"error": "Sin autorización para crear permisos"}), 403

        idcliente = _get_request_idcliente_or_claims(claims)
        err = _guard_tenant_access_or_403(claims, idcliente)
        if err:
            return err

        data = request.get_json() or {}
        nombre = (data.get("nombre") or "").strip()
        codigo = (data.get("codigo") or "").strip()
        descripcion = data.get("descripcion")
        activo = bool(data.get("activo", True))

        if not nombre or not codigo:
            return jsonify({"error": "Faltan campos requeridos"}), 400

        permiso = Permiso(idcliente=idcliente, nombre=nombre, codigo=codigo, descripcion=descripcion, activo=activo)
        db.session.add(permiso)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({"error": "Código ya existe para este cliente"}), 409

        return jsonify({"message": "Permiso creado", "idpermiso": permiso.idpermiso}), 201


    # ====== Asignar permisos a perfil ======
    @app.route("/api/perfiles/<int:idperfil>/permisos", methods=["POST"])
    @jwt_required()
    def asignar_permisos_a_perfil(idperfil):
        claims = get_jwt()
        perfil = Perfil.query.get_or_404(idperfil)
        err = _guard_tenant_access_or_403(claims, perfil.idcliente)
        if err:
            return err

        data = request.get_json() or {}
        permisos = data.get("permisos") or []

        for item in permisos:
            idpermiso = item.get("idpermiso")
            permitido = bool(item.get("permitido", True))
            if not idpermiso:
                continue

            rel = PerfilPermiso.query.filter_by(idcliente=perfil.idcliente, idperfil=idperfil, idpermiso=idpermiso).first()
            if rel:
                rel.permitido = permitido
            else:
                db.session.add(PerfilPermiso(idcliente=perfil.idcliente, idperfil=idperfil, idpermiso=idpermiso, permitido=permitido))

        db.session.commit()
        return jsonify({"message": "Permisos actualizados"}), 200

    # ====== Permisos de un usuario ======
    @app.route("/api/usuarios/<int:idusuario>/permisos", methods=["GET"])
    @jwt_required()
    def permisos_usuario(idusuario):
        claims = get_jwt()
        user = Usuario.query.get_or_404(idusuario)
        err = _guard_tenant_access_or_403(claims, user.idcliente)
        if err:
            return err

        rows = (
            db.session.query(Permiso.codigo)
            .join(PerfilPermiso, Permiso.idpermiso == PerfilPermiso.idpermiso)
            .filter(
                Permiso.idcliente == user.idcliente,
                PerfilPermiso.idcliente == user.idcliente,
                PerfilPermiso.idperfil == user.idperfil,
                PerfilPermiso.permitido.is_(True)
            )
            .all()
        )
        codigos = [r[0] for r in rows]
        return jsonify({"permisos": codigos}), 200

    print("✅ Rutas de permisos registradas en app principal.")


        # ================================================================
    # CRUD de permisos base (solo superadmin)
    # ================================================================
    @app.route("/api/permisos/<int:idpermiso>", methods=["PUT"])
    @jwt_required()
    def update_permiso(idpermiso):
        claims = get_jwt()
        permiso = Permiso.query.get_or_404(idpermiso)

        # Solo superadmin o cliente admin del mismo tenant
        if not (_is_superadmin(claims) or _is_cliente_admin(claims)):
            return jsonify({"error": "Sin autorización para editar permisos"}), 403

        err = _guard_tenant_access_or_403(claims, permiso.idcliente)
        if err:
            return err

        data = request.get_json() or {}
        permiso.nombre = data.get("nombre", permiso.nombre)
        permiso.codigo = data.get("codigo", permiso.codigo)
        permiso.descripcion = data.get("descripcion", permiso.descripcion)
        permiso.activo = bool(data.get("activo", permiso.activo))
        db.session.commit()
        return jsonify({"message": "Permiso actualizado correctamente"})


    @app.route("/api/permisos/<int:idpermiso>", methods=["DELETE"])
    @jwt_required()
    def delete_permiso(idpermiso):
        claims = get_jwt()
        permiso = Permiso.query.get_or_404(idpermiso)

        if not (_is_superadmin(claims) or _is_cliente_admin(claims)):
            return jsonify({"error": "Sin autorización para eliminar permisos"}), 403

        err = _guard_tenant_access_or_403(claims, permiso.idcliente)
        if err:
            return err

        db.session.delete(permiso)
        db.session.commit()
        return jsonify({"message": "Permiso eliminado"}), 200



    # ============================================================
    # 🔹 Obtener todos los permisos asignados a un perfil
    # ============================================================
    @app.route("/api/perfiles/<int:idperfil>/permisos", methods=["GET"])
    @jwt_required()
    def obtener_permisos_por_perfil(idperfil):
        claims = get_jwt()
        perfilid_token = claims.get("perfilid")

        # 🔹 Obtener el cliente al que pertenece el perfil consultado
        perfil_obj = Perfil.query.get_or_404(idperfil)
        idcliente = perfil_obj.idcliente

        # 🔹 Superadmin puede ver los permisos del cliente del perfil
        # 🔹 Usuarios normales solo si pertenecen a ese cliente
        if perfilid_token != 0:
            token_idcliente = claims.get("idcliente")
            if token_idcliente != idcliente:
                return jsonify({"error": "Acceso denegado al cliente"}), 403

        # 🔹 Traer permisos del cliente y del cliente base (1), junto con asignaciones
        permisos_combinados = (
            db.session.query(
                Permiso.idpermiso,
                Permiso.nombre,
                Permiso.codigo,
                Permiso.descripcion,
                PerfilPermiso.permitido,
                Permiso.idcliente
            )
            .outerjoin(
                PerfilPermiso,
                (Permiso.idpermiso == PerfilPermiso.idpermiso)
                & (PerfilPermiso.idperfil == idperfil)
                & (PerfilPermiso.idcliente == idcliente)
            )
            .filter(
                (Permiso.idcliente == idcliente) |
                (Permiso.idcliente == 1)
            )
            .order_by(Permiso.codigo.asc())
            .all()
        )

        # 🔄 Eliminar duplicados por código (prioridad al permiso del cliente)
        permisos_dict = {}
        for pid, nombre, codigo, descripcion, permitido, pidcliente in permisos_combinados:
            if codigo not in permisos_dict or pidcliente == idcliente:
                permisos_dict[codigo] = {
                    "idpermiso": pid,
                    "nombre": nombre,
                    "codigo": codigo,
                    "descripcion": descripcion,
                    "permitido": bool(permitido) if permitido is not None else False
                }

        result = list(permisos_dict.values())
        print(f"[DEBUG] Cliente {idcliente}: retornando {len(result)} permisos únicos para perfil {idperfil}")
        return jsonify(result)



    # ============================================================
    # 🔹 Actualizar permisos asignados a un perfil
    # ============================================================
    @app.route("/api/perfiles/<int:idperfil>/permisos", methods=["PUT"])
    @jwt_required()
    def actualizar_permisos_por_perfil(idperfil):
        claims = get_jwt()
        perfilid_token = claims.get("perfilid")

        # 🔹 Cliente y perfil objetivo
        perfil_obj = Perfil.query.get_or_404(idperfil)
        idcliente = perfil_obj.idcliente

        # 🔹 Obtiene el perfil del usuario autenticado
        perfil_usuario = Perfil.query.filter_by(idperfil=perfilid_token).first()

        # 🔐 Reglas de autorización:
        # - Superadmin (perfilid_token == 0) siempre puede
        # - El perfil llamado "Administrador" del mismo cliente también puede
        # - Otros perfiles requieren tener explícitamente el permiso "editar_permisos"
        if perfilid_token != 0:
            if not perfil_usuario or perfil_usuario.idcliente != idcliente:
                return jsonify({"error": "No autorizado para modificar otro cliente"}), 403
            if perfil_usuario.nombre.lower() != "administrador":
                if not _perfil_tiene_permiso(perfilid_token, idcliente, "editar_permisos"):
                    return jsonify({"error": "No autorizado para modificar permisos"}), 403

        data = request.get_json() or {}
        permisos = data.get("permisos", [])

        creados = 0
        actualizados = 0

        for p in permisos:
            idpermiso = p.get("idpermiso")
            permitido = p.get("permitido", False)
            codigo = p.get("codigo")
            nombre = p.get("nombre")
            descripcion = p.get("descripcion", "")

            permiso = Permiso.query.get(idpermiso)

            # 🔹 Si el permiso es de otro cliente, clonarlo
            if not permiso or permiso.idcliente != idcliente:
                if not codigo:
                    base = Permiso.query.get(idpermiso)
                    if base:
                        codigo = base.codigo
                        nombre = base.nombre
                        descripcion = base.descripcion
                permiso_local = Permiso.query.filter_by(idcliente=idcliente, codigo=codigo).first()
                if not permiso_local:
                    permiso_local = Permiso(
                        idcliente=idcliente,
                        nombre=nombre,
                        codigo=codigo,
                        descripcion=descripcion,
                        activo=True,
                    )
                    db.session.add(permiso_local)
                    db.session.flush()
                    creados += 1
                permiso = permiso_local

            rel = PerfilPermiso.query.filter_by(
                idperfil=idperfil,
                idpermiso=permiso.idpermiso,
                idcliente=idcliente
            ).first()

            if rel:
                rel.permitido = permitido
                actualizados += 1
            else:
                db.session.add(PerfilPermiso(
                    idcliente=idcliente,
                    idperfil=idperfil,
                    idpermiso=permiso.idpermiso,
                    permitido=permitido
                ))
                creados += 1

        db.session.commit()
        print(f"[PERMISOS] Cliente {idcliente}: {creados} permisos creados, {actualizados} actualizados.")
        return jsonify({"message": f"Permisos actualizados ({creados} nuevos, {actualizados} actualizados)."})

    


    @app.route("/api/mis_permisos", methods=["GET"])
    @jwt_required()
    def mis_permisos():
        claims = get_jwt()
        idperfil = claims.get("perfilid")
        idcliente = claims.get("idcliente")

        # Superadmin ve todo
        if idperfil == 0:
            permisos = Permiso.query.with_entities(Permiso.codigo).distinct().all()
            return jsonify([p.codigo for p in permisos])

        # Cliente: obtener permisos activos y permitidos
        permisos = (
            db.session.query(Permiso.codigo)
            .join(PerfilPermiso, Permiso.idpermiso == PerfilPermiso.idpermiso)
            .filter(
                PerfilPermiso.idcliente == idcliente,
                PerfilPermiso.idperfil == idperfil,
                PerfilPermiso.permitido == True,
                Permiso.activo == True,
            )
            .all()
        )
        codigos = [p.codigo for p in permisos]
        return jsonify(codigos)