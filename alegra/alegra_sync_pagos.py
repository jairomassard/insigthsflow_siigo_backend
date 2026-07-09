"""
Sync de /payments (type=in y type=out) -> alegra_pagos + alegra_pago_facturas.

CONFIRMADO con dato real en Fase 0 (Importadora NGC):
- type=in = pagos recibidos de clientes (aplican contra 'invoices').
- type=out = pagos a proveedores (aplican contra 'bills').
- Dos formas mutuamente excluyentes de aplicar un pago: (a) contra
  documentos - campo 'invoices'/'bills' (mismo shape que en notas credito:
  id, number, date, amount, total, balance, un pago puede cubrir varias) o
  (b) directo contra una cuenta contable - campo 'categories' (id, name,
  price, total, behavior), sin documentos asociados.
- bankAccount embebido ({id, name, type}) y client embebido en version
  liviana (id, name, phone, identification).
- status incluye 'void' (pago anulado) - se guarda tal cual, el filtrado de
  anulados queda para la capa de reporting, no para el sync.

NOTA - no confirmado con JSON crudo: el nombre literal del campo de valor
total del pago (columna 'valor') se asume 'total' por convencion Alegra,
con 'amount' como respaldo si 'total' no viene.

INCREMENTAL (2026-07-09): sin date_after confirmado para /payments, se pide
ordenado DESC por fecha (order_field/order_direction NO confirmados contra
dato real para este endpoint especifico - asumidos por el mismo patron de
/journals y /bills, ajustar si no funciona como se espera) y se para al
llegar al ultimo pago ya sincronizado.

LIMITACION ACEPTADA (2026-07-09): a diferencia de facturas/compras/notas, un
pago NO se vuelve a re-consultar si ya paso la fecha de corte - un pago no
tiene "saldo pendiente" que evolucione con el tiempo como una factura, solo
podria cambiar si se anula (estado='void') despues de sincronizado. Ese caso
raro no se cubre por el incremental; se corrige en el proximo sync completo.
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
from models_alegra import AlegraPago, AlegraPagoFactura
from alegra.alegra_api import ALEGRA_BASE_URL_DEFAULT, paginate
from alegra.alegra_sync_catalogos import _credenciales_alegra


def _parse_fecha(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        return None


def _sync_pagos_por_tipo(idcliente: int, email: str, token: str, tipo: str) -> tuple[int, int, int]:
    total, nuevos, actualizados = 0, 0, 0
    campo_documentos = "invoices" if tipo == "in" else "bills"
    documento_tipo = "factura" if tipo == "in" else "compra"

    # PERFORMANCE (2026-07-09): ver nota igual en alegra_sync_facturas.py.
    existentes = {
        p.alegra_id: p
        for p in AlegraPago.query.filter_by(idcliente=idcliente, tipo=tipo).all()
    }

    ultima_fecha = db.session.query(func.max(AlegraPago.fecha)).filter(
        AlegraPago.idcliente == idcliente, AlegraPago.tipo == tipo
    ).scalar()

    # limit=10, mismo motivo que en /journals e /invoices (ver comentarios ahi).
    for p in paginate(
        ALEGRA_BASE_URL_DEFAULT, email, token, "payments",
        extra_params={"type": tipo, "order_field": "date", "order_direction": "DESC"},
        limit=10,
    ):
        if ultima_fecha and p.get("date"):
            fecha_pago = _parse_fecha(p["date"])
            if fecha_pago and fecha_pago < ultima_fecha:
                break

        total += 1
        alegra_id = str(p.get("id"))

        pago = existentes.get(alegra_id)
        is_new = pago is None
        if is_new:
            pago = AlegraPago(idcliente=idcliente, alegra_id=alegra_id, tipo=tipo)
            db.session.add(pago)
            db.session.flush()  # necesita pago.id para el puente
            existentes[alegra_id] = pago

        banco = p.get("bankAccount") or {}
        cliente = p.get("client") or {}
        categorias = p.get("categories") or []

        pago.fecha = _parse_fecha(p.get("date"))
        pago.valor = p.get("total") if p.get("total") is not None else p.get("amount")
        pago.metodo_pago = p.get("paymentMethod")
        pago.banco_id = str(banco.get("id")) if banco.get("id") is not None else None
        pago.tercero_id = str(cliente.get("id")) if cliente.get("id") is not None else None
        pago.categoria_contable_id = str(categorias[0].get("id")) if categorias else None
        pago.estado = p.get("status")

        # Puente solo del pago que se esta tocando en esta pasada.
        AlegraPagoFactura.query.filter_by(pago_id=pago.id).delete()
        for doc in p.get(campo_documentos) or []:
            db.session.add(AlegraPagoFactura(
                idcliente=idcliente,
                pago_id=pago.id,
                documento_tipo=documento_tipo,
                documento_alegra_id=str(doc.get("id")),
                monto_aplicado=doc.get("amount"),
            ))

        if is_new:
            nuevos += 1
        else:
            actualizados += 1

    db.session.commit()

    return total, nuevos, actualizados


def sync_pagos_desde_alegra(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)

    total_in, nuevos_in, act_in = _sync_pagos_por_tipo(idcliente, email, token, "in")
    total_out, nuevos_out, act_out = _sync_pagos_por_tipo(idcliente, email, token, "out")

    return (
        f"Pagos Alegra (idcliente={idcliente}): "
        f"recibidos(in)={total_in} (nuevos={nuevos_in}, actualizados={act_in}), "
        f"emitidos(out)={total_out} (nuevos={nuevos_out}, actualizados={act_out})."
    )


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
        print(sync_pagos_desde_alegra(cid))
