from datetime import date
from models import (
    db,
    Permiso,
    PerfilPermiso,
    ClientePaquete,
    PaqueteInsightflow,
    PaquetePermiso,
)


def obtener_codigos_permitidos_cliente(idcliente: int) -> set[str]:
    """
    Retorna los códigos de permisos incluidos en los paquetes activos del cliente.

    Reglas:
    - cliente_paquetes.activo = True
    - paquetes_insightflow.activo = True
    - paquete_permisos.activo = True
    - fecha_inicio <= hoy, si existe
    - fecha_fin >= hoy o NULL
    """

    if not idcliente:
        return set()

    hoy = date.today()

    rows = (
        db.session.query(PaquetePermiso.codigo_permiso)
        .join(
            PaqueteInsightflow,
            PaqueteInsightflow.idpaquete == PaquetePermiso.idpaquete
        )
        .join(
            ClientePaquete,
            ClientePaquete.idpaquete == PaqueteInsightflow.idpaquete
        )
        .filter(
            ClientePaquete.idcliente == idcliente,
            ClientePaquete.activo.is_(True),
            PaqueteInsightflow.activo.is_(True),
            PaquetePermiso.activo.is_(True),
            db.or_(
                ClientePaquete.fecha_inicio.is_(None),
                ClientePaquete.fecha_inicio <= hoy
            ),
            db.or_(
                ClientePaquete.fecha_fin.is_(None),
                ClientePaquete.fecha_fin >= hoy
            ),
        )
        .distinct()
        .all()
    )

    return {r[0] for r in rows if r[0]}


def cliente_tiene_permiso_en_paquete(idcliente: int, codigo_permiso: str) -> bool:
    """
    Verifica si el permiso está incluido en alguno de los paquetes activos del cliente.
    """

    if not idcliente or not codigo_permiso:
        return False

    codigos = obtener_codigos_permitidos_cliente(idcliente)
    return codigo_permiso in codigos


def obtener_permisos_disponibles_para_cliente(idcliente: int) -> list[dict]:
    """
    Retorna los permisos que el cliente tiene derecho a usar por paquete.

    Fuente:
    - Primero busca permiso local del cliente.
    - Si no existe local, usa permiso plantilla del cliente 1.
    - Nunca retorna permisos fuera del paquete contratado.
    """

    codigos_permitidos = obtener_codigos_permitidos_cliente(idcliente)

    if not codigos_permitidos:
        return []

    permisos_locales = (
        Permiso.query
        .filter(
            Permiso.idcliente == idcliente,
            Permiso.codigo.in_(codigos_permitidos),
            Permiso.activo.is_(True),
        )
        .all()
    )

    permisos_base = (
        Permiso.query
        .filter(
            Permiso.idcliente == 1,
            Permiso.codigo.in_(codigos_permitidos),
            Permiso.activo.is_(True),
        )
        .all()
    )

    permisos_por_codigo = {}

    # Primero base
    for p in permisos_base:
        permisos_por_codigo[p.codigo] = p

    # Luego local, para que tenga prioridad
    for p in permisos_locales:
        permisos_por_codigo[p.codigo] = p

    salida = []
    for codigo in sorted(codigos_permitidos):
        p = permisos_por_codigo.get(codigo)
        if not p:
            continue

        salida.append({
            "idpermiso": p.idpermiso,
            "idcliente": p.idcliente,
            "codigo": p.codigo,
            "nombre": p.nombre,
            "descripcion": p.descripcion,
            "activo": p.activo,
        })

    return salida


def clonar_permiso_base_para_cliente(idcliente: int, codigo_permiso: str):
    """
    Si el permiso pertenece al paquete del cliente, pero aún no existe localmente,
    lo clona desde el cliente 1.

    Retorna el permiso local.
    """

    if not cliente_tiene_permiso_en_paquete(idcliente, codigo_permiso):
        return None

    permiso_local = Permiso.query.filter_by(
        idcliente=idcliente,
        codigo=codigo_permiso
    ).first()

    if permiso_local:
        return permiso_local

    permiso_base = Permiso.query.filter_by(
        idcliente=1,
        codigo=codigo_permiso
    ).first()

    if not permiso_base:
        return None

    nuevo = Permiso(
        idcliente=idcliente,
        nombre=permiso_base.nombre,
        codigo=permiso_base.codigo,
        descripcion=permiso_base.descripcion,
        activo=permiso_base.activo,
    )

    db.session.add(nuevo)
    db.session.flush()

    return nuevo


def obtener_codigos_permitidos_por_perfil_y_paquete(idcliente: int, idperfil: int) -> list[str]:
    """
    Retorna la intersección entre:
    - permisos incluidos en el paquete contratado
    - permisos permitidos al perfil
    """

    codigos_paquete = obtener_codigos_permitidos_cliente(idcliente)

    if not codigos_paquete:
        return []

    rows = (
        db.session.query(Permiso.codigo)
        .join(PerfilPermiso, PerfilPermiso.idpermiso == Permiso.idpermiso)
        .filter(
            Permiso.idcliente == idcliente,
            Permiso.activo.is_(True),
            Permiso.codigo.in_(codigos_paquete),
            PerfilPermiso.idcliente == idcliente,
            PerfilPermiso.idperfil == idperfil,
            PerfilPermiso.permitido.is_(True),
        )
        .distinct()
        .all()
    )

    return [r[0] for r in rows if r[0]]