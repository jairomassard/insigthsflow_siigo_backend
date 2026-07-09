"""
Sync de /invoices -> alegra_facturas + alegra_factura_items.

Campos de cabecera confirmados con dato real en Fase 0 (Importadora NGC y
Nelsy/Jose): items[] embebidos, balance/totalPaid directos, payments[]
embebidos, seller (puede venir null a nivel de factura individual sin que
eso indique un problema - el catalogo /sellers si aplica), stamp (CUFE, solo
si el cliente factura electronicamente), tax[] por item con categoryRule.

NOTA - no confirmado con JSON crudo (a diferencia de /journals, que si se
verifico): los nombres literales 'client' (tercero), 'currency' y el id de
producto dentro de items[] se asumen por convencion de Alegra (camelCase,
mismo patron que 'client' en /journals y 'provider' en /bills). Si al probar
contra datos reales alguno de estos difiere, ajustar solo el punto marcado.

INCREMENTAL (2026-07-09): /invoices SI soporta date_after del lado del
servidor (confirmado Fase 0) - se usa para traer solo lo nuevo desde la
ultima factura sincronizada. Pero una factura vieja puede cambiar de saldo
(pago o nota credito posterior) sin que cambie su fecha de emision - por eso
NO alcanza con "solo lo nuevo": ademas se re-consultan puntualmente (por ID)
las facturas que en nuestra BD sigan con balance > 0, porque son las unicas
que todavia pueden estar cambiando. Las que ya estan en balance = 0 se
asumen cerradas y no se vuelven a tocar hasta el proximo sync completo.
"""

import os
import sys
from datetime import datetime

# Debe cargarse ANTES que cualquier import que toque crypto_utils/config (ver
# nota igual en alegra_sync_catalogos.py).
from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import func

from models import db
from models_alegra import AlegraFactura, AlegraFacturaItem
from alegra.alegra_api import ALEGRA_BASE_URL_DEFAULT, get, paginate
from alegra.alegra_sync_catalogos import _credenciales_alegra


def _parse_fecha(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        return None


def sync_facturas_desde_alegra(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)
    total, nuevos, actualizados = 0, 0, 0

    # PERFORMANCE (2026-07-09): trae todas las facturas existentes en un solo
    # SELECT en vez de un .filter_by().first() por cada una.
    existentes = {
        f.alegra_id: f
        for f in AlegraFactura.query.filter_by(idcliente=idcliente).all()
    }

    ultima_fecha = db.session.query(func.max(AlegraFactura.fecha)).filter(
        AlegraFactura.idcliente == idcliente
    ).scalar()

    ids_procesados = set()

    def _procesar(inv):
        nonlocal total, nuevos, actualizados

        total += 1
        alegra_id = str(inv.get("id"))
        ids_procesados.add(alegra_id)

        factura = existentes.get(alegra_id)
        is_new = factura is None
        if is_new:
            factura = AlegraFactura(idcliente=idcliente, alegra_id=alegra_id)
            db.session.add(factura)
            db.session.flush()  # necesita factura.id para los items
            existentes[alegra_id] = factura

        cliente = inv.get("client") or {}
        vendedor = inv.get("seller") or {}
        cc = inv.get("costCenter")

        factura.fecha = _parse_fecha(inv.get("date"))
        factura.vencimiento = _parse_fecha(inv.get("dueDate"))
        factura.tercero_id = str(cliente.get("id")) if cliente.get("id") is not None else None
        factura.tercero_nombre = cliente.get("name")
        factura.vendedor_id = str(vendedor.get("id")) if vendedor.get("id") is not None else None
        factura.centro_costo_id = str(cc.get("id")) if isinstance(cc, dict) and cc.get("id") is not None else None
        factura.subtotal = inv.get("subtotal")
        factura.impuestos_total = inv.get("tax")
        factura.total = inv.get("total")
        factura.balance = inv.get("balance")
        factura.total_paid = inv.get("totalPaid")
        factura.estado = inv.get("status")
        # CONFIRMADO 2026-07-09: el campo 'currency' esta AUSENTE por completo
        # (no viene como null, no existe la clave) cuando la factura esta en
        # la moneda local de la cuenta - se asume COP dado que el alcance de
        # InsightsFlow/Alegra es exclusivamente Colombia. Si el campo si
        # viene (factura en moneda extranjera), se usa su codigo real.
        moneda_obj = inv.get("currency")
        factura.moneda = moneda_obj.get("code") if isinstance(moneda_obj, dict) else "COP"
        factura.retenciones = inv.get("retentions")
        factura.payments = inv.get("payments")
        factura.stamp = inv.get("stamp")

        # Reemplaza items solo de la factura que se esta tocando en esta
        # pasada (no de todas las existentes - en modo incremental solo se
        # toca un subconjunto chico, no tiene sentido borrar/reinsertar todo).
        AlegraFacturaItem.query.filter_by(factura_id=factura.id).delete()
        for item in inv.get("items") or []:
            db.session.add(AlegraFacturaItem(
                factura_id=factura.id,
                idcliente=idcliente,
                producto_id=str(item.get("id")) if item.get("id") is not None else None,
                descripcion=item.get("description") or item.get("name"),
                cantidad=item.get("quantity"),
                precio=item.get("price"),
                descuento_valor=item.get("discount"),
                total_item=item.get("total"),
                tax=item.get("tax"),
            ))

        if is_new:
            nuevos += 1
        else:
            actualizados += 1

    # limit=10 (no el DEFAULT_LIMIT=30 general) - mismo problema confirmado en
    # /journals 2026-07-08: con objetos pesados embebidos (items/payments/tax
    # por linea), limit=30 da 503 Service Unavailable.
    extra_params = {"date_after": ultima_fecha.isoformat()} if ultima_fecha else None
    for inv in paginate(ALEGRA_BASE_URL_DEFAULT, email, token, "invoices", extra_params=extra_params, limit=10):
        _procesar(inv)

    # Re-consulta puntual de facturas viejas que sigan con saldo pendiente -
    # son las unicas que pueden haber cambiado sin que cambiara su fecha.
    if ultima_fecha:
        abiertas = [
            f for f in existentes.values()
            if f.alegra_id not in ids_procesados and (f.balance or 0) > 0
        ]
        for f in abiertas:
            inv = get(ALEGRA_BASE_URL_DEFAULT, email, token, f"invoices/{f.alegra_id}")
            _procesar(inv)

    db.session.commit()

    return f"Facturas Alegra (idcliente={idcliente}): total={total}, nuevos={nuevos}, actualizados={actualizados}."


if __name__ == "__main__":
    try:
        from app import app
    except Exception:
        print("No se pudo importar 'app' desde app.py.")
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
        print(sync_facturas_desde_alegra(cid))
