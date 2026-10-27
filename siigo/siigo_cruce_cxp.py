from collections import defaultdict
from datetime import date, datetime


# Emparejamiento entre el reporte de cuentas por pagar de Siigo
# (siigo_cuentasporcobrar) y las compras (siigo_compras), usado por
# /siigo/cross-accounts-payable.
#
# FIX (2026-10-27): antes el cruce armaba un dict
# {(factura_proveedor, NIT): compra}. Los Documentos Soporte de personas
# naturales repiten su propia numeracion (DS-1, DS-2... por cada proveedor),
# asi que varias compras comparten llave y el dict se quedaba solo con la
# ultima: las demas nunca se marcaban pagadas (quedaban con saldo = total
# desde el insert de staging) y el saldo de la CxP caia en el documento
# equivocado. Confirmado con datos reales de Binaria: 129 DS (~$168M)
# mostrados como pendientes que Siigo tiene "Pagada" (ej. DS-1-1432,
# DS-1-1313), y 0 casos con llave unica. Ahora cada fila de la CxP se
# empareja con UNA compra entre las que comparten llave (por valor y
# vencimiento), y toda compra que no quede emparejada se considera pagada.


def _as_date(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return datetime.fromisoformat(str(value)[:10]).date()
    except Exception:
        return None


def _diferencia_valor(cuenta, compra):
    """Distancia entre el valor de la fila CxP y la compra. Se compara contra
    el total y contra el total neto de retencion, porque segun el documento
    Siigo reporta en CxP el "Total a Pagar" (neto) y siigo_compras.total puede
    estar en bruto (Documento Soporte)."""
    valor = abs(float(cuenta.valor or 0))
    total = float(compra.total or 0)
    neto = total - float(getattr(compra, "retencion_total", None) or 0)
    return min(abs(valor - total), abs(valor - neto))


def _diferencia_dias(cuenta, compra):
    a = _as_date(cuenta.fecha_vencimiento)
    b = _as_date(compra.vencimiento) or _as_date(compra.fecha)
    if not a or not b:
        return 10**6
    return abs((a - b).days)


def emparejar_cxp_con_compras(cuentas, compras):
    """
    Devuelve (asignacion, sin_compra):
    - asignacion: {id(compra): [cuentas...]} para cada compra que quedo con
      al menos una fila de la CxP de Siigo.
    - sin_compra: filas de la CxP cuya llave no corresponde a ninguna compra.

    Reglas:
    - Llave = (factura_proveedor, proveedor_identificacion), igual que antes.
    - Si la llave tiene una sola compra, todas sus filas van a esa compra
      (comportamiento de siempre).
    - Si tiene varias, las filas positivas se reparten de mayor a menor
      valor, prefiriendo una compra todavia sin fila, y luego la de valor
      mas parecido y vencimiento mas cercano.
    - Las filas negativas/cero (reversos que Siigo reporta como linea aparte,
      ej. +2.008M y -2.008M) se suman a la compra ya emparejada con valor mas
      parecido, para que se netee contra su positiva y no ensucie otra compra.
    """
    compras_por_llave = defaultdict(list)
    for compra in compras:
        compras_por_llave[(compra.factura_proveedor, compra.proveedor_identificacion)].append(compra)

    cuentas_por_llave = defaultdict(list)
    for cuenta in cuentas:
        cuentas_por_llave[(cuenta.documento, cuenta.proveedor_identificacion)].append(cuenta)

    asignacion = {}
    sin_compra = []

    for llave, filas in cuentas_por_llave.items():
        candidatas = compras_por_llave.get(llave)

        if not candidatas:
            sin_compra.extend(filas)
            continue

        if len(candidatas) == 1:
            asignacion.setdefault(id(candidatas[0]), []).extend(filas)
            continue

        positivas = sorted(
            [f for f in filas if float(f.valor or 0) > 0],
            key=lambda f: float(f.valor or 0),
            reverse=True,
        )
        no_positivas = [f for f in filas if float(f.valor or 0) <= 0]

        usadas = set()

        for fila in positivas:
            elegida = min(
                candidatas,
                key=lambda c: (
                    id(c) in usadas,
                    _diferencia_valor(fila, c),
                    _diferencia_dias(fila, c),
                ),
            )
            usadas.add(id(elegida))
            asignacion.setdefault(id(elegida), []).append(fila)

        for fila in no_positivas:
            pool = [c for c in candidatas if id(c) in usadas] or candidatas
            elegida = min(
                pool,
                key=lambda c: (_diferencia_valor(fila, c), _diferencia_dias(fila, c)),
            )
            usadas.add(id(elegida))
            asignacion.setdefault(id(elegida), []).append(fila)

    return asignacion, sin_compra
