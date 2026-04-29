# permisos_routes.py
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from sqlalchemy.exc import IntegrityError

from models import db, Usuario, Perfil, Permiso, PerfilPermiso
from decoradores_seguridad import _perfil_tiene_permiso
from licenciamiento import (
    obtener_codigos_permitidos_cliente,
    obtener_permisos_disponibles_para_cliente,
    clonar_permiso_base_para_cliente,
    obtener_codigos_permitidos_por_perfil_y_paquete,
)


# -----------------------
# Helper functions
# -----------------------
def _is_superadmin(claims: dict) -> bool:
    return claims.get("perfilid") == 0


def _is_cliente_admin(claims: dict) -> bool:
    """
    Determina si el usuario autenticado tiene perfil de 'Administrador'
    dentro de su cliente.
    """
    if _is_superadmin(claims):
        return True

    perfilid = claims.get("perfilid")
    idcliente = claims.get("idcliente")

    if not perfilid or not idcliente:
        return False

    perfil = Perfil.query.filter_by(
        idperfil=perfilid,
        idcliente=idcliente
    ).first()

    if perfil and perfil.nombre and perfil.nombre.lower() == "administrador":
        return True

    return False


def _get_request_idcliente_or_claims(claims: dict) -> int | None:
    """
    SuperAdmin puede pasar ?idcliente=.
    Si no lo pasa, usamos cliente 1 como catálogo base de permisos.
    Usuario cliente usa siempre idcliente del token.
    """
    if _is_superadmin(claims):
        q = request.args.get("idcliente", type=int)
        return q or 1

    return claims.get("idcliente")


def _guard_tenant_access_or_403(claims: dict, target_idcliente: int | None):
    """
    Valida acceso multitenant.
    SuperAdmin puede ver cualquier cliente.
    Usuario cliente solo su propio cliente.
    """
    if _is_superadmin(claims):
        if target_idcliente is None:
            return jsonify({"error": "Falta idcliente"}), 400
        return None

    token_idcliente = claims.get("idcliente")

    if token_idcliente is None or token_idcliente != target_idcliente:
        return jsonify({"error": "Acceso denegado al tenant"}), 403

    return None


# -----------------------
# Registro de rutas
# -----------------------
def register_permisos_routes(app):

    # ============================================================
    # Listar permisos disponibles
    # ============================================================
    @app.route("/api/permisos", methods=["GET"])
    @jwt_required()
    def list_permisos():
        """
        SuperAdmin:
        - Si envía ?idcliente=, ve permisos de ese cliente.
        - Si no envía idcliente, ve permisos base del cliente 1.

        Cliente:
        - Solo ve permisos incluidos en su paquete contratado.
        """
        claims = get_jwt()
        idcliente = _get_request_idcliente_or_claims(claims)

        err = _guard_tenant_access_or_403(claims, idcliente)
        if err:
            return err

        if _is_superadmin(claims):
            permisos = (
                Permiso.query
                .filter_by(idcliente=idcliente)
                .order_by(Permiso.codigo.asc())
                .all()
            )

            return jsonify([
                {
                    "idpermiso": p.idpermiso,
                    "nombre": p.nombre,
                    "codigo": p.codigo,
                    "descripcion": p.descripcion,
                    "activo": p.activo,
                    "idcliente": p.idcliente,
                    "created_at": p.created_at.isoformat() if p.created_at else None
                }
                for p in permisos
            ])

        # Cliente normal: solo permisos contratados por paquete
        permisos = obtener_permisos_disponibles_para_cliente(idcliente)

        return jsonify([
            {
                "idpermiso": p["idpermiso"],
                "nombre": p["nombre"],
                "codigo": p["codigo"],
                "descripcion": p["descripcion"],
                "activo": p["activo"],
                "idcliente": p["idcliente"],
                "created_at": None,
            }
            for p in permisos
        ])


    # ============================================================
    # Crear permiso base / permiso de sistema
    # Recomendación SaaS: solo SuperAdmin.
    # ============================================================
    @app.route("/api/permisos", methods=["POST"])
    @jwt_required()
    def create_permiso():
        claims = get_jwt()

        if not _is_superadmin(claims):
            return jsonify({"error": "Solo SuperAdmin puede crear permisos del sistema"}), 403

        idcliente = _get_request_idcliente_or_claims(claims)

        data = request.get_json() or {}
        nombre = (data.get("nombre") or "").strip()
        codigo = (data.get("codigo") or "").strip()
        descripcion = data.get("descripcion")
        activo = bool(data.get("activo", True))

        if not nombre or not codigo:
            return jsonify({"error": "Faltan campos requeridos: nombre y codigo"}), 400

        permiso = Permiso(
            idcliente=idcliente,
            nombre=nombre,
            codigo=codigo,
            descripcion=descripcion,
            activo=activo
        )

        db.session.add(permiso)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({"error": "Código ya existe para este cliente"}), 409

        return jsonify({
            "message": "Permiso creado",
            "idpermiso": permiso.idpermiso
        }), 201


    # ============================================================
    # Asignar permisos a perfil - POST legacy
    # Se deja compatible, pero aplica la misma regla de paquete.
    # ============================================================
    @app.route("/api/perfiles/<int:idperfil>/permisos", methods=["POST"])
    @jwt_required()
    def asignar_permisos_a_perfil(idperfil):
        return actualizar_permisos_por_perfil(idperfil)


    # ============================================================
    # Permisos de un usuario
    # ============================================================
    @app.route("/api/usuarios/<int:idusuario>/permisos", methods=["GET"])
    @jwt_required()
    def permisos_usuario(idusuario):
        claims = get_jwt()
        user = Usuario.query.get_or_404(idusuario)

        err = _guard_tenant_access_or_403(claims, user.idcliente)
        if err:
            return err

        if _is_superadmin(claims):
            rows = Permiso.query.with_entities(Permiso.codigo).distinct().all()
            codigos = [r[0] for r in rows if r[0]]
            return jsonify({"permisos": codigos}), 200

        codigos = obtener_codigos_permitidos_por_perfil_y_paquete(
            user.idcliente,
            user.idperfil
        )

        return jsonify({"permisos": codigos}), 200


    # ============================================================
    # Editar permiso
    # Recomendación SaaS: solo SuperAdmin.
    # ============================================================
    @app.route("/api/permisos/<int:idpermiso>", methods=["PUT"])
    @jwt_required()
    def update_permiso(idpermiso):
        claims = get_jwt()

        if not _is_superadmin(claims):
            return jsonify({"error": "Solo SuperAdmin puede editar permisos del sistema"}), 403

        permiso = Permiso.query.get_or_404(idpermiso)

        data = request.get_json() or {}
        permiso.nombre = data.get("nombre", permiso.nombre)
        permiso.codigo = data.get("codigo", permiso.codigo)
        permiso.descripcion = data.get("descripcion", permiso.descripcion)

        if "activo" in data:
            permiso.activo = bool(data["activo"])

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({"error": "Código ya existe para este cliente"}), 409

        return jsonify({"message": "Permiso actualizado correctamente"})


    # ============================================================
    # Eliminar permiso
    # Recomendación SaaS: solo SuperAdmin.
    # ============================================================
    @app.route("/api/permisos/<int:idpermiso>", methods=["DELETE"])
    @jwt_required()
    def delete_permiso(idpermiso):
        claims = get_jwt()

        if not _is_superadmin(claims):
            return jsonify({"error": "Solo SuperAdmin puede eliminar permisos del sistema"}), 403

        permiso = Permiso.query.get_or_404(idpermiso)

        db.session.delete(permiso)
        db.session.commit()

        return jsonify({"message": "Permiso eliminado"}), 200


    # ============================================================
    # Obtener permisos asignables a un perfil
    # ============================================================
    @app.route("/api/perfiles/<int:idperfil>/permisos", methods=["GET"])
    @jwt_required()
    def obtener_permisos_por_perfil(idperfil):
        claims = get_jwt()
        perfil_obj = Perfil.query.get_or_404(idperfil)
        idcliente = perfil_obj.idcliente

        err = _guard_tenant_access_or_403(claims, idcliente)
        if err:
            return err

        # SuperAdmin también debe ver solo los permisos disponibles para ese cliente.
        # Si el cliente no tiene paquete, devolvemos vacío para evitar asignaciones indebidas.
        permisos_disponibles = obtener_permisos_disponibles_para_cliente(idcliente)

        if not permisos_disponibles:
            return jsonify([]), 200

        ids_permisos = [p["idpermiso"] for p in permisos_disponibles if p.get("idpermiso")]

        relaciones = (
            PerfilPermiso.query
            .filter(
                PerfilPermiso.idcliente == idcliente,
                PerfilPermiso.idperfil == idperfil,
                PerfilPermiso.idpermiso.in_(ids_permisos)
            )
            .all()
        )

        permitido_por_id = {
            rel.idpermiso: bool(rel.permitido)
            for rel in relaciones
        }

        result = []

        for p in permisos_disponibles:
            result.append({
                "idpermiso": p["idpermiso"],
                "nombre": p["nombre"],
                "codigo": p["codigo"],
                "descripcion": p["descripcion"],
                "permitido": permitido_por_id.get(p["idpermiso"], False)
            })

        print(
            f"[PERMISOS] Cliente {idcliente}: "
            f"{len(result)} permisos disponibles para perfil {idperfil}"
        )

        return jsonify(result), 200


    # ============================================================
    # Actualizar permisos asignados a un perfil
    # ============================================================
    @app.route("/api/perfiles/<int:idperfil>/permisos", methods=["PUT"])
    @jwt_required()
    def actualizar_permisos_por_perfil(idperfil):
        claims = get_jwt()
        perfilid_token = claims.get("perfilid")

        perfil_obj = Perfil.query.get_or_404(idperfil)
        idcliente = perfil_obj.idcliente

        err = _guard_tenant_access_or_403(claims, idcliente)
        if err:
            return err

        # Reglas de autorización:
        # - SuperAdmin puede.
        # - Administrador del cliente puede.
        # - Otros perfiles requieren editar_perfiles o editar_permisos.
        if not _is_superadmin(claims):
            perfil_usuario = Perfil.query.filter_by(
                idperfil=perfilid_token,
                idcliente=idcliente
            ).first()

            if not perfil_usuario:
                return jsonify({"error": "No autorizado para modificar permisos"}), 403

            es_admin_cliente = perfil_usuario.nombre and perfil_usuario.nombre.lower() == "administrador"

            if not es_admin_cliente:
                puede_editar = (
                    _perfil_tiene_permiso(perfilid_token, idcliente, "editar_perfiles")
                    or _perfil_tiene_permiso(perfilid_token, idcliente, "editar_permisos")
                )

                if not puede_editar:
                    return jsonify({"error": "No autorizado para modificar permisos"}), 403

        data = request.get_json() or {}
        permisos = data.get("permisos", [])

        codigos_contratados = obtener_codigos_permitidos_cliente(idcliente)

        if not codigos_contratados:
            return jsonify({
                "error": "El cliente no tiene paquetes activos o permisos contratados.",
                "motivo": "sin_paquete_activo"
            }), 403

        creados = 0
        actualizados = 0
        rechazados = []

        for p in permisos:
            permitido = bool(p.get("permitido", False))
            codigo = p.get("codigo")
            idpermiso = p.get("idpermiso")

            permiso_original = None

            if idpermiso:
                permiso_original = Permiso.query.get(idpermiso)

            if not codigo and permiso_original:
                codigo = permiso_original.codigo

            if not codigo:
                rechazados.append({
                    "idpermiso": idpermiso,
                    "motivo": "permiso_sin_codigo"
                })
                continue

            if codigo not in codigos_contratados:
                rechazados.append({
                    "codigo": codigo,
                    "motivo": "permiso_no_incluido_en_paquete"
                })
                continue

            permiso_local = Permiso.query.filter_by(
                idcliente=idcliente,
                codigo=codigo
            ).first()

            if not permiso_local:
                permiso_local = clonar_permiso_base_para_cliente(idcliente, codigo)
                if permiso_local:
                    creados += 1

            if not permiso_local:
                rechazados.append({
                    "codigo": codigo,
                    "motivo": "no_existe_permiso_base_para_clonar"
                })
                continue

            rel = PerfilPermiso.query.filter_by(
                idperfil=idperfil,
                idpermiso=permiso_local.idpermiso,
                idcliente=idcliente
            ).first()

            if rel:
                rel.permitido = permitido
                actualizados += 1
            else:
                db.session.add(PerfilPermiso(
                    idcliente=idcliente,
                    idperfil=idperfil,
                    idpermiso=permiso_local.idpermiso,
                    permitido=permitido
                ))
                creados += 1

        db.session.commit()

        print(
            f"[PERMISOS] Cliente {idcliente}: "
            f"{creados} creados, {actualizados} actualizados, "
            f"{len(rechazados)} rechazados."
        )

        return jsonify({
            "message": "Permisos actualizados correctamente.",
            "creados": creados,
            "actualizados": actualizados,
            "rechazados": rechazados
        }), 200


    # ============================================================
    # Mis permisos para frontend/sidebar
    # ============================================================
    @app.route("/api/mis_permisos", methods=["GET"])
    @jwt_required()
    def mis_permisos():
        claims = get_jwt()
        idperfil = claims.get("perfilid")
        idcliente = claims.get("idcliente")

        # SuperAdmin ve todo
        if idperfil == 0:
            permisos = Permiso.query.with_entities(Permiso.codigo).distinct().all()
            return jsonify([p.codigo for p in permisos if p.codigo])

        if not idcliente or not idperfil:
            return jsonify([]), 200

        codigos = obtener_codigos_permitidos_por_perfil_y_paquete(
            idcliente,
            idperfil
        )

        return jsonify(codigos), 200

    print("✅ Rutas de permisos registradas en app principal con control por paquetes.")