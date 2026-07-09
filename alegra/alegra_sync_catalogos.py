"""
Sync de los 7 catalogos base de Alegra. Deben correr antes que cualquier
tabla transaccional (movimientos, facturas, compras, pagos), porque esas
las referencian por FK blanda (ver Plan Maestro seccion 4.5, punto 2).

PERFORMANCE (2026-07-09): cada sync trae de una sola vez TODOS los registros
existentes de idcliente en un dict (1 SELECT), en vez de hacer un
.filter_by().first() por cada item de la API (N SELECTs, uno por registro).
Contra una cuenta con volumen real (1904 productos) el patron viejo tardaba
varios minutos por la latencia de ida y vuelta a Railway en cada consulta
individual - confirmado en vivo, no solo sospechado.
"""

import os
import sys

# Debe cargarse ANTES que cualquier import que toque crypto_utils/config: ese
# modulo lee APP_CRYPTO_KEY del entorno al importarse (no de forma diferida),
# asi que si algo lo importa antes de que .env este cargado, queda con la
# llave en None para siempre en ese proceso y dec() deja de desencriptar en
# silencio (bug real encontrado 2026-07-08 corriendo esto via `python -m`).
# En Railway no aplica (las env vars ya estan inyectadas antes de arrancar).
from dotenv import load_dotenv
load_dotenv()

from crypto_utils import dec
from models import db
from models_alegra import (
    AlegraCredencial,
    AlegraCuentaContable,
    AlegraTercero,
    AlegraVendedor,
    AlegraCentroCosto,
    AlegraRetencionCatalogo,
    AlegraImpuestoCatalogo,
    AlegraProducto,
)
from alegra.alegra_api import (
    ALEGRA_BASE_URL_DEFAULT,
    get,
    paginate,
    get_categories_tree,
    flatten_categories,
)


def _credenciales_alegra(idcliente: int):
    cred = AlegraCredencial.query.filter_by(idcliente=idcliente).first()
    if not cred:
        raise RuntimeError(f"Credenciales de Alegra no configuradas para idcliente={idcliente}")

    token = dec(cred.token)
    if not token:
        raise RuntimeError(f"No se pudo desencriptar el token de Alegra para idcliente={idcliente}")

    return cred.email, token


def sync_categorias_desde_alegra(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)
    tree = get_categories_tree(ALEGRA_BASE_URL_DEFAULT, email, token)
    nodos = tree if isinstance(tree, list) else (tree.get("results") or [])
    flat = flatten_categories(nodos)

    existentes = {
        c.alegra_id: c
        for c in AlegraCuentaContable.query.filter_by(idcliente=idcliente).all()
    }

    nuevos, actualizados = 0, 0
    for c in flat:
        cuenta = existentes.get(c["id"])
        is_new = cuenta is None
        if is_new:
            cuenta = AlegraCuentaContable(idcliente=idcliente, alegra_id=c["id"])
            db.session.add(cuenta)

        cuenta.code = c["code"]
        cuenta.name = c["name"]
        cuenta.type = c["type"]
        cuenta.nature = c["nature"]
        cuenta.use = c["use"]
        cuenta.category_rule_key = c["category_rule_key"]
        cuenta.parent_id = c["parent_id"]

        if is_new:
            nuevos += 1
        else:
            actualizados += 1

    db.session.commit()
    return f"Cuentas contables Alegra (idcliente={idcliente}): total={len(flat)}, nuevos={nuevos}, actualizados={actualizados}."


def _tipo_tercero(type_raw) -> str:
    # NOTA: no confirmado con dato real en Fase 0 (solo se confirmo que `type`
    # puede venir como [] para contactos sin etiquetar, ej. bancos). Los
    # valores 'client'/'provider' son la convencion estandar documentada de
    # Alegra, pero falta validarlos contra un payload real antes de confiar
    # en este mapeo en produccion.
    if isinstance(type_raw, list):
        valores = {str(v).lower() for v in type_raw}
        es_cliente = "client" in valores
        es_proveedor = "provider" in valores
        if es_cliente and es_proveedor:
            return "ambos"
        if es_cliente:
            return "cliente"
        if es_proveedor:
            return "proveedor"
        return "otro"
    return str(type_raw).lower() if type_raw else "otro"


def sync_terceros_desde_alegra(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)
    total, nuevos, actualizados = 0, 0, 0

    existentes = {
        t.alegra_id: t
        for t in AlegraTercero.query.filter_by(idcliente=idcliente).all()
    }

    for c in paginate(ALEGRA_BASE_URL_DEFAULT, email, token, "contacts"):
        total += 1
        alegra_id = str(c.get("id"))
        tercero = existentes.get(alegra_id)
        is_new = tercero is None
        if is_new:
            tercero = AlegraTercero(idcliente=idcliente, alegra_id=alegra_id)
            db.session.add(tercero)
            existentes[alegra_id] = tercero

        tercero.nombre = c.get("name")
        tercero.identificacion = c.get("identification")
        tercero.tipo = _tipo_tercero(c.get("type"))
        tercero.regimen = c.get("regime")
        tercero.responsabilidades_fiscales = c.get("fiscalResponsabilities")
        tercero.uuid_alegra = c.get("uuid")

        if is_new:
            nuevos += 1
        else:
            actualizados += 1

    db.session.commit()
    return f"Terceros Alegra (idcliente={idcliente}): total={total}, nuevos={nuevos}, actualizados={actualizados}."


def sync_vendedores_desde_alegra(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)
    total, nuevos, actualizados = 0, 0, 0

    existentes = {
        v.alegra_id: v
        for v in AlegraVendedor.query.filter_by(idcliente=idcliente).all()
    }

    for s in paginate(ALEGRA_BASE_URL_DEFAULT, email, token, "sellers"):
        total += 1
        alegra_id = str(s.get("id"))
        vendedor = existentes.get(alegra_id)
        is_new = vendedor is None
        if is_new:
            vendedor = AlegraVendedor(idcliente=idcliente, alegra_id=alegra_id)
            db.session.add(vendedor)
            existentes[alegra_id] = vendedor

        vendedor.nombre = s.get("name")
        vendedor.identificacion = s.get("identification")
        vendedor.activo = (s.get("status") == "active")

        if is_new:
            nuevos += 1
        else:
            actualizados += 1

    db.session.commit()
    return f"Vendedores Alegra (idcliente={idcliente}): total={total}, nuevos={nuevos}, actualizados={actualizados}."


def sync_centros_costo_desde_alegra(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)
    total, nuevos, actualizados = 0, 0, 0

    existentes = {
        c.alegra_id: c
        for c in AlegraCentroCosto.query.filter_by(idcliente=idcliente).all()
    }

    for cc in paginate(ALEGRA_BASE_URL_DEFAULT, email, token, "cost-centers"):
        total += 1
        alegra_id = str(cc.get("id"))
        centro = existentes.get(alegra_id)
        is_new = centro is None
        if is_new:
            centro = AlegraCentroCosto(idcliente=idcliente, alegra_id=alegra_id)
            db.session.add(centro)
            existentes[alegra_id] = centro

        centro.nombre = cc.get("name")
        centro.codigo = cc.get("code")

        if is_new:
            nuevos += 1
        else:
            actualizados += 1

    db.session.commit()
    return f"Centros de costo Alegra (idcliente={idcliente}): total={total}, nuevos={nuevos}, actualizados={actualizados}."


def sync_retenciones_catalogo_desde_alegra(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)
    total, nuevos, actualizados = 0, 0, 0

    existentes = {
        r.alegra_id: r
        for r in AlegraRetencionCatalogo.query.filter_by(idcliente=idcliente).all()
    }

    for r in paginate(ALEGRA_BASE_URL_DEFAULT, email, token, "retentions"):
        total += 1
        alegra_id = str(r.get("id"))
        cat = existentes.get(alegra_id)
        is_new = cat is None
        if is_new:
            cat = AlegraRetencionCatalogo(idcliente=idcliente, alegra_id=alegra_id)
            db.session.add(cat)
            existentes[alegra_id] = cat

        ref = r.get("idRetentionReference")
        cat.name = r.get("name")
        cat.type = r.get("type")
        cat.percentage = r.get("percentage")
        cat.id_retention_reference = str(ref) if ref is not None else None
        cat.status = r.get("status")

        if is_new:
            nuevos += 1
        else:
            actualizados += 1

    db.session.commit()
    return f"Catalogo de retenciones Alegra (idcliente={idcliente}): total={total}, nuevos={nuevos}, actualizados={actualizados}."


def sync_impuestos_catalogo_desde_alegra(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)
    total, nuevos, actualizados = 0, 0, 0

    existentes = {
        i.alegra_id: i
        for i in AlegraImpuestoCatalogo.query.filter_by(idcliente=idcliente).all()
    }

    # /taxes viene envuelto en {total, results[]} (confirmado en Fase 0) -
    # paginate() ya maneja ambos shapes (lista plana o dict con 'results').
    for t in paginate(ALEGRA_BASE_URL_DEFAULT, email, token, "taxes"):
        total += 1
        alegra_id = str(t.get("id"))
        imp = existentes.get(alegra_id)
        is_new = imp is None
        if is_new:
            imp = AlegraImpuestoCatalogo(idcliente=idcliente, alegra_id=alegra_id)
            db.session.add(imp)
            existentes[alegra_id] = imp

        imp.name = t.get("name")
        imp.percentage = t.get("percentage")
        imp.type = t.get("type")
        imp.rate = t.get("rate")

        if is_new:
            nuevos += 1
        else:
            actualizados += 1

    db.session.commit()
    return f"Catalogo de impuestos Alegra (idcliente={idcliente}): total={total}, nuevos={nuevos}, actualizados={actualizados}."


def sync_productos_desde_alegra(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)
    total, nuevos, actualizados = 0, 0, 0

    existentes = {
        p.alegra_id: p
        for p in AlegraProducto.query.filter_by(idcliente=idcliente).all()
    }

    for p in paginate(ALEGRA_BASE_URL_DEFAULT, email, token, "items"):
        total += 1
        alegra_id = str(p.get("id"))
        prod = existentes.get(alegra_id)
        is_new = prod is None
        if is_new:
            prod = AlegraProducto(idcliente=idcliente, alegra_id=alegra_id)
            db.session.add(prod)
            existentes[alegra_id] = prod

        categoria = p.get("category") or {}
        accounting = p.get("accounting") or {}
        cuenta_inventario = accounting.get("inventory") or {}
        cuenta_costo_venta = accounting.get("inventariablePurchase") or {}
        inventario = p.get("inventory") or {}

        prod.code = p.get("code")
        prod.name = p.get("name")
        prod.type = p.get("type")
        prod.categoria_id = str(categoria.get("id")) if categoria.get("id") is not None else None
        prod.cuenta_inventario_id = str(cuenta_inventario.get("id")) if cuenta_inventario.get("id") is not None else None
        prod.cuenta_costo_venta_id = str(cuenta_costo_venta.get("id")) if cuenta_costo_venta.get("id") is not None else None
        prod.impuestos = p.get("tax")
        prod.precios = p.get("price")
        prod.bodegas = inventario.get("warehouses")

        if is_new:
            nuevos += 1
        else:
            actualizados += 1

    db.session.commit()
    return f"Productos Alegra (idcliente={idcliente}): total={total}, nuevos={nuevos}, actualizados={actualizados}."


def sync_catalogos_desde_alegra(idcliente: int) -> list[str]:
    """Corre los 7 catalogos base en orden. No incluye datos transaccionales
    (journals/invoices/bills/payments), esos van en modulos separados."""
    funciones = (
        sync_categorias_desde_alegra,
        sync_terceros_desde_alegra,
        sync_vendedores_desde_alegra,
        sync_centros_costo_desde_alegra,
        sync_retenciones_catalogo_desde_alegra,
        sync_impuestos_catalogo_desde_alegra,
        sync_productos_desde_alegra,
    )
    return [fn(idcliente) for fn in funciones]


# --- Ejecucion opcional por consola ---
# Uso (correr desde backend/, con -m para que el paquete 'alegra' resuelva bien):
#   python -m alegra.alegra_sync_catalogos 1   (1 es el numero del cliente)
#   IDCLIENTE=1 python -m alegra.alegra_sync_catalogos
# En PowerShell, si aparece UnicodeEncodeError al importar app.py (emojis en
# los print de app.py vs consola cp1252), forzar UTF-8 antes:
#   $env:PYTHONIOENCODING = "utf-8"
if __name__ == "__main__":
    try:
        from app import app
    except Exception:
        print("No se pudo importar 'app' desde app.py. Ejecuta esta funcion via endpoint o ajusta este bloque.")
        sys.exit(1)

    cid = None
    if len(sys.argv) >= 2 and sys.argv[1].isdigit():
        cid = int(sys.argv[1])
    else:
        env_id = os.getenv("IDCLIENTE")
        if env_id and env_id.isdigit():
            cid = int(env_id)

    if not cid:
        print("Falta idcliente. Usa argumento numerico o variable de entorno IDCLIENTE.")
        sys.exit(1)

    with app.app_context():
        for linea in sync_catalogos_desde_alegra(cid):
            print(linea)
