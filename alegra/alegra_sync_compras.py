"""
Sync de /bills -> alegra_compras + alegra_compra_items + alegra_compra_retenciones.

CONFIRMADO con dato real en Fase 0 (Importadora NGC, proveedor "Transporte
Porto Romero"):
- 'provider' embebido en version liviana (id, name, identification, ...).
- balance/totalPaid directos en la factura de proveedor.
- purchases.categories[] (gasto/servicio directo a cuenta) O
  purchases.items[] (compra de producto/inventario, id coincide con /items)
  son mutuamente excluyentes.
- retentions[] shape real: {id, name, percentage, amount, calculatedBy,
  exchangeRate, type, isAssumed} - una compra puede tener varias retenciones
  simultaneas.
- /bills NO tiene rango de fechas, solo 'date'/'dueDate' exactos.

INCREMENTAL (2026-07-09): sin date_after, se pide ordenado DESC por fecha y
se para al llegar a la ultima compra ya sincronizada (mismo truco que
/journals). Ademas de lo nuevo, se re-consultan puntualmente las compras
viejas que sigan con saldo pendiente (balance > 0), porque un pago posterior
puede cambiar su estado sin cambiar su fecha (mismo principio que
alegra_sync_facturas.py).
"""

import os
import sys
from datetime import datetime

# Debe cargarse ANTES que cualquier import que toque crypto_utils/config (ver
# nota igual en alegra_sync_catalogos.py).
from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from models import db
from models_alegra import AlegraCompra, AlegraCompraItem, AlegraCompraRetencion
from alegra.alegra_api import ALEGRA_BASE_URL_DEFAULT, get, paginate
from alegra.alegra_sync_catalogos import _credenciales_alegra


def _parse_fecha(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        return None


def sync_compras_desde_alegra(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)
    total, nuevos, actualizados = 0, 0, 0

    existentes = {
        c.alegra_id: c
        for c in AlegraCompra.query.filter_by(idcliente=idcliente).all()
    }

    ultima_fecha = db.session.query(func.max(AlegraCompra.fecha)).filter(
        AlegraCompra.idcliente == idcliente
    ).scalar()

    ids_procesados = set()

    def _procesar(bill):
        nonlocal total, nuevos, actualizados

        total += 1
        alegra_id = str(bill.get("id"))
        ids_procesados.add(alegra_id)

        compra = existentes.get(alegra_id)
        is_new = compra is None
        if is_new:
            compra = AlegraCompra(idcliente=idcliente, alegra_id=alegra_id)
            try:
                # SAVEPOINT propio: ver nota igual en alegra_sync_pagos.py.
                with db.session.begin_nested():
                    db.session.add(compra)
                    db.session.flush()  # necesita compra.id para items/retenciones
            except IntegrityError:
                compra = AlegraCompra.query.filter_by(
                    idcliente=idcliente, alegra_id=alegra_id
                ).first()
                is_new = False
            existentes[alegra_id] = compra

        proveedor = bill.get("provider") or {}
        cc = bill.get("costCenter")
        number_template = bill.get("numberTemplate") or {}

        compra.fecha = _parse_fecha(bill.get("date"))
        compra.vencimiento = _parse_fecha(bill.get("dueDate"))
        compra.proveedor_id = str(proveedor.get("id")) if proveedor.get("id") is not None else None
        compra.proveedor_nombre = proveedor.get("name")
        compra.centro_costo_id = str(cc.get("id")) if isinstance(cc, dict) and cc.get("id") is not None else None
        # numberTemplate.fullNumber es el numero/referencia de la factura del
        # proveedor (confirmado con dato real: formato libre por proveedor,
        # ej. "TC-455283"), NO el id interno de Alegra - equivalente a
        # SiigoCompra.factura_proveedor.
        compra.factura_proveedor = number_template.get("fullNumber") or number_template.get("number")
        compra.total = bill.get("total")
        compra.balance = bill.get("balance")
        compra.total_paid = bill.get("totalPaid")
        compra.estado = bill.get("status")

        # purchases.categories[] (gasto/servicio) y purchases.items[] (producto)
        # son mutuamente excluyentes - se reemplazan ambas listas de la compra
        # que se esta tocando en esta pasada.
        purchases = bill.get("purchases") or {}
        AlegraCompraItem.query.filter_by(compra_id=compra.id).delete()

        for cat in purchases.get("categories") or []:
            db.session.add(AlegraCompraItem(
                compra_id=compra.id,
                idcliente=idcliente,
                tipo="categoria",
                cuenta_contable_id=str(cat.get("id")) if cat.get("id") is not None else None,
                descripcion=cat.get("name"),
                cantidad=None,
                precio=cat.get("price"),
                subtotal=None,
                total=cat.get("total"),
                tax=cat.get("tax"),
            ))

        for it in purchases.get("items") or []:
            db.session.add(AlegraCompraItem(
                compra_id=compra.id,
                idcliente=idcliente,
                tipo="item",
                producto_id=str(it.get("id")) if it.get("id") is not None else None,
                descripcion=it.get("name"),
                cantidad=it.get("quantity"),
                precio=it.get("price"),
                subtotal=it.get("subtotal"),
                total=it.get("total"),
                tax=it.get("tax"),
            ))

        AlegraCompraRetencion.query.filter_by(compra_id=compra.id).delete()
        for ret in bill.get("retentions") or []:
            db.session.add(AlegraCompraRetencion(
                idcliente=idcliente,
                compra_id=compra.id,
                retention_id=str(ret.get("id")) if ret.get("id") is not None else None,
                name=ret.get("name"),
                percentage=ret.get("percentage"),
                amount=ret.get("amount"),
                calculated_by=ret.get("calculatedBy"),
                exchange_rate=ret.get("exchangeRate"),
                is_assumed=bool(ret.get("isAssumed") or False),
            ))

        if is_new:
            nuevos += 1
        else:
            actualizados += 1

    # limit=10, mismo motivo que en /journals e /invoices (ver comentarios ahi).
    for bill in paginate(
        ALEGRA_BASE_URL_DEFAULT, email, token, "bills",
        extra_params={"order_field": "date", "order_direction": "DESC"},
        limit=10,
    ):
        if ultima_fecha and bill.get("date"):
            fecha_bill = _parse_fecha(bill["date"])
            if fecha_bill and fecha_bill < ultima_fecha:
                break
        _procesar(bill)

    if ultima_fecha:
        abiertas = [
            c for c in existentes.values()
            if c.alegra_id not in ids_procesados and (c.balance or 0) > 0
        ]
        for c in abiertas:
            bill = get(ALEGRA_BASE_URL_DEFAULT, email, token, f"bills/{c.alegra_id}")
            _procesar(bill)

    db.session.commit()

    return f"Compras Alegra (idcliente={idcliente}): total={total}, nuevos={nuevos}, actualizados={actualizados}."


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
        print(sync_compras_desde_alegra(cid))
