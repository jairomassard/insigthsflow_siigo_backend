"""
Sync de /credit-notes -> alegra_notas_credito + alegra_nota_credito_facturas.

CONFIRMADO con dato real en Fase 0: el campo que referencia la(s) factura(s)
afectada(s) es 'invoices' (arreglo de {id, prefix, number, date, dueDate,
amount, total, balance}) - una nota puede aplicar a varias facturas, de ahi
la tabla puente. NO existe date_after/date_before para este endpoint, solo
'date' exacto.

CONFIRMADO con dato real 2026-07-10 (idcliente=15, alegra_id=5): la cabecera
SI trae 'subtotal' y 'tax' (numerico, no array), mismo shape que /invoices -
de ahi columnas subtotal/impuestos_total, usadas para netear ingresos
operacionales pre-IVA en construir_pnl_alegra_facturas (app.py). El campo
'totalApplied' tambien se confirmo con ese mismo JSON.

NOTA - no confirmado: que /credit-notes acepte order_field/order_direction
como /journals y /bills - se asume por el mismo patron de la API, a
verificar si el stop-early de abajo no funciona como se espera.

INCREMENTAL (2026-07-09): como no hay date_after, se pide ordenado DESC por
fecha y se para de paginar al llegar a la ultima nota ya sincronizada (mismo
truco que /journals). Una nota credito puede seguir con saldo sin aplicar
(balance > 0) y aplicarse mas tarde contra otra factura - por eso, ademas de
lo nuevo, se re-consultan puntualmente las notas viejas que sigan abiertas
(mismo principio que alegra_sync_facturas.py).
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
from models_alegra import AlegraNotaCredito, AlegraNotaCreditoFactura
from alegra.alegra_api import ALEGRA_BASE_URL_DEFAULT, get, paginate
from alegra.alegra_sync_catalogos import _credenciales_alegra


def _parse_fecha(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        return None


def sync_notas_credito_desde_alegra(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)
    total, nuevos, actualizados = 0, 0, 0

    existentes = {
        n.alegra_id: n
        for n in AlegraNotaCredito.query.filter_by(idcliente=idcliente).all()
    }

    ultima_fecha = db.session.query(func.max(AlegraNotaCredito.fecha)).filter(
        AlegraNotaCredito.idcliente == idcliente
    ).scalar()

    ids_procesados = set()

    def _procesar(cn):
        nonlocal total, nuevos, actualizados

        total += 1
        alegra_id = str(cn.get("id"))
        ids_procesados.add(alegra_id)

        nota = existentes.get(alegra_id)
        is_new = nota is None
        if is_new:
            nota = AlegraNotaCredito(idcliente=idcliente, alegra_id=alegra_id)
            try:
                # SAVEPOINT propio: ver nota igual en alegra_sync_pagos.py.
                with db.session.begin_nested():
                    db.session.add(nota)
                    db.session.flush()  # necesita nota.id para el puente
            except IntegrityError:
                nota = AlegraNotaCredito.query.filter_by(
                    idcliente=idcliente, alegra_id=alegra_id
                ).first()
                is_new = False
            existentes[alegra_id] = nota

        cliente = cn.get("client") or {}

        nota.fecha = _parse_fecha(cn.get("date"))
        nota.subtotal = cn.get("subtotal")
        nota.impuestos_total = cn.get("tax")
        nota.total = cn.get("total")
        nota.balance = cn.get("balance")
        nota.total_applied = cn.get("totalApplied")
        nota.cliente_id = str(cliente.get("id")) if cliente.get("id") is not None else None
        nota.estado = cn.get("status")

        AlegraNotaCreditoFactura.query.filter_by(nota_credito_id=nota.id).delete()
        for factura_ref in cn.get("invoices") or []:
            db.session.add(AlegraNotaCreditoFactura(
                idcliente=idcliente,
                nota_credito_id=nota.id,
                factura_alegra_id=str(factura_ref.get("id")),
                monto_aplicado=factura_ref.get("amount"),
            ))

        if is_new:
            nuevos += 1
        else:
            actualizados += 1

    # limit=10, mismo motivo que en /journals e /invoices (ver comentarios ahi).
    for cn in paginate(
        ALEGRA_BASE_URL_DEFAULT, email, token, "credit-notes",
        extra_params={"order_field": "date", "order_direction": "DESC"},
        limit=10,
    ):
        if ultima_fecha and cn.get("date"):
            fecha_nota = _parse_fecha(cn["date"])
            if fecha_nota and fecha_nota < ultima_fecha:
                break
        _procesar(cn)

    if ultima_fecha:
        abiertas = [
            n for n in existentes.values()
            if n.alegra_id not in ids_procesados and (n.balance or 0) > 0
        ]
        for n in abiertas:
            cn = get(ALEGRA_BASE_URL_DEFAULT, email, token, f"credit-notes/{n.alegra_id}")
            _procesar(cn)

    db.session.commit()

    return f"Notas credito Alegra (idcliente={idcliente}): total={total}, nuevos={nuevos}, actualizados={actualizados}."


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
        print(sync_notas_credito_desde_alegra(cid))
