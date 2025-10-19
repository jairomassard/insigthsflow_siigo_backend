from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt
from models import db, Perfil, Permiso, PerfilPermiso

# ------------------------------------------------------------
# 🔐 1. Helper: detectar si el usuario es superadmin
# ------------------------------------------------------------
def _is_superadmin(claims: dict) -> bool:
    """
    Retorna True si el token corresponde al superadmin global.
    """
    return claims.get("perfilid") == 0


# ------------------------------------------------------------
# 🔐 2. Helper: detectar si el perfil tiene el permiso solicitado
# ------------------------------------------------------------
def _perfil_tiene_permiso(idperfil: int, idcliente: int, codigo_permiso: str) -> bool:
    """
    Verifica si un perfil dado tiene permitido acceder al permiso con ese código.
    """
    permiso = Permiso.query.filter_by(codigo=codigo_permiso, idcliente=idcliente).first()
    if not permiso:
        return False

    rel = PerfilPermiso.query.filter_by(
        idperfil=idperfil,
        idpermiso=permiso.idpermiso,
        idcliente=idcliente
    ).first()

    return bool(rel and rel.permitido)


# ------------------------------------------------------------
# 🧱 3. Decorador principal
# ------------------------------------------------------------
def permiso_requerido(codigo_permiso: str):
    """
    Decorador que protege rutas Flask verificando si el usuario actual
    tiene asignado el permiso indicado. Compatible con tu modelo multi-tenant.
    Uso: @jwt_required() + @permiso_requerido("codigo_permiso")
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            claims = get_jwt()

            # 1️⃣ Superadmin: siempre permitido
            if _is_superadmin(claims):
                return fn(*args, **kwargs)

            idperfil = claims.get("perfilid")
            idcliente = claims.get("idcliente")

            if not idperfil or not idcliente:
                return jsonify({"error": "Token inválido: falta idperfil o idcliente"}), 403

            # 2️⃣ Verificar si el perfil tiene el permiso
            if not _perfil_tiene_permiso(idperfil, idcliente, codigo_permiso):
                return jsonify({
                    "error": f"Acceso denegado: falta permiso '{codigo_permiso}'",
                    "permiso": codigo_permiso
                }), 403

            # ✅ Permiso concedido
            return fn(*args, **kwargs)

        return wrapper
    return decorator
