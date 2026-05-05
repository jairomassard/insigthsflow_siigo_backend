from datetime import datetime, date
from decimal import Decimal, InvalidOperation

from sqlalchemy import and_

from models import (
    db,
    SiigoCompra,
    SiigoCompraItem,
    SiigoDocumentoSoporteApiStaging,
)


def _to_decimal(value, default=None):
    if value is None:
        return default
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return default


def _to_float(value, default=None):
    if value is None:
        return default
    try:
        return float(value)
    except Exception:
        return default


def _parse_fecha_desde(value):
    if not value:
        return date(date.today().year, 1, 1)

    if isinstance(value, date):
        return value

    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
    except Exception:
        return date(date.today().year, 1, 1)


def _sum_items_total(raw_json):
    """
    Calcula el bruto desde los items.
    En Documento Soporte, s.total suele venir neto después de retenciones.
    Los items normalmente traen el valor bruto/base del documento.
    """
    items = []
    if isinstance(raw_json, dict):
        items = raw_json.get("items") or []

    total = Decimal("0")

    if not isinstance(items, list):
        return total

    for item in items:
        if not isinstance(item, dict):
            continue

        item_total = _to_decimal(item.get("total"), None)

        if item_total is None:
            price = _to_decimal(item.get("price"), Decimal("0"))
            quantity = _to_decimal(item.get("quantity"), Decimal("1"))
            item_total = price * quantity

        total += item_total

    return total


def _sum_item_taxes(item):
    """
    Guarda IVA/impuestos del item si vienen en la API.
    No usamos retenciones como impuestos de item.
    """
    taxes = item.get("taxes") if isinstance(item, dict) else None
    total = Decimal("0")

    if not isinstance(taxes, list):
        return total

    for tax in taxes:
        if isinstance(tax, dict):
            total += _to_decimal(tax.get("value"), Decimal("0"))

    return total


def _calcular_total_bruto(staging_row):
    """
    Prioridad:
    1. Suma raw_json.items.total
    2. staging.total + staging.retentions_total
    3. staging.total
    """
    bruto_items = _sum_items_total(staging_row.raw_json or {})

    if bruto_items and bruto_items > 0:
        return bruto_items

    total_neto = _to_decimal(staging_row.total, Decimal("0"))
    retenciones = _to_decimal(staging_row.retentions_total, Decimal("0"))

    bruto_estimado = total_neto + retenciones

    if bruto_estimado > 0:
        return bruto_estimado

    return total_neto


def insertar_documentos_soporte_desde_staging(
    idcliente: int,
    fecha_desde=None,
    dry_run: bool = False,
    max_registros: int | None = None,
):
    """
    Inserta en siigo_compras únicamente DS nuevos provenientes de staging.

    Reglas:
    - Solo stamp_status = Accepted
    - Solo total > 0
    - Solo items_count > 0
    - Solo fecha >= fecha_desde
    - Solo si no existe ya en siigo_compras
    - No usa balance API como saldo definitivo
    """

    fecha_desde = _parse_fecha_desde(fecha_desde)

    query = (
        db.session.query(SiigoDocumentoSoporteApiStaging)
        .outerjoin(
            SiigoCompra,
            and_(
                SiigoCompra.idcliente == SiigoDocumentoSoporteApiStaging.idcliente,
                SiigoCompra.idcompra == SiigoDocumentoSoporteApiStaging.name,
            ),
        )
        .filter(SiigoDocumentoSoporteApiStaging.idcliente == idcliente)
        .filter(SiigoCompra.id.is_(None))
        .filter(SiigoDocumentoSoporteApiStaging.stamp_status == "Accepted")
        .filter(SiigoDocumentoSoporteApiStaging.total > 0)
        .filter(SiigoDocumentoSoporteApiStaging.items_count > 0)
        .filter(SiigoDocumentoSoporteApiStaging.fecha >= fecha_desde)
        .order_by(SiigoDocumentoSoporteApiStaging.fecha.asc(), SiigoDocumentoSoporteApiStaging.name.asc())
    )

    if max_registros:
        query = query.limit(max_registros)

    candidatos = query.all()

    if dry_run:
        return {
            "modo": "dry_run",
            "mensaje": "Simulación finalizada. No se insertó información.",
            "cliente": idcliente,
            "fecha_desde": fecha_desde.isoformat(),
            "candidatos": len(candidatos),
            "preview": [
                {
                    "name": s.name,
                    "fecha": s.fecha.isoformat() if s.fecha else None,
                    "proveedor_nombre": s.proveedor_nombre,
                    "proveedor_identificacion": s.proveedor_identificacion,
                    "cost_center": s.cost_center,
                    "total_neto_api": float(s.total or 0),
                    "retentions_total": float(s.retentions_total or 0),
                    "total_bruto_estimado": float(_calcular_total_bruto(s)),
                    "factura_proveedor": s.factura_proveedor,
                    "stamp_status": s.stamp_status,
                    "items_count": s.items_count,
                }
                for s in candidatos[:30]
            ],
        }

    insertadas = 0
    items_insertados = 0
    omitidas = 0
    errores = 0
    detalle_errores = []

    for s in candidatos:
        try:
            # Doble validación para evitar carrera/duplicados
            existe = SiigoCompra.query.filter_by(
                idcliente=idcliente,
                idcompra=s.name,
            ).first()

            if existe:
                omitidas += 1
                continue

            raw_json = s.raw_json or {}
            raw_items = raw_json.get("items") if isinstance(raw_json, dict) else []
            if not isinstance(raw_items, list):
                raw_items = []

            total_bruto = _calcular_total_bruto(s)

            compra = SiigoCompra(
                idcliente=idcliente,
                idcompra=s.name,
                fecha=s.fecha,
                vencimiento=s.vencimiento,
                proveedor_nombre=s.proveedor_nombre,
                proveedor_identificacion=s.proveedor_identificacion,
                estado="pendiente",
                total=total_bruto,
                saldo=total_bruto,
                cost_center=s.cost_center,
                creado=s.created_siigo,
                factura_proveedor=s.factura_proveedor,
            )

            db.session.add(compra)
            db.session.flush()

            for item in raw_items:
                if not isinstance(item, dict):
                    continue

                descripcion = item.get("description") or f"Documento soporte {s.name}"
                cantidad = _to_decimal(item.get("quantity"), Decimal("1"))

                # Seguimos la lógica de /purchases: precio = item.price.
                # El total del encabezado queda con el bruto correcto.
                precio = _to_decimal(item.get("price"), None)
                if precio is None:
                    precio = _to_decimal(item.get("total"), Decimal("0"))

                impuestos = _sum_item_taxes(item)

                codigo = item.get("code")

                compra_item = SiigoCompraItem(
                    compra_id=compra.id,
                    idcliente=idcliente,
                    descripcion=descripcion,
                    cantidad=cantidad,
                    precio=precio,
                    impuestos=impuestos,
                    codigo=codigo,
                )

                db.session.add(compra_item)
                items_insertados += 1

            insertadas += 1

        except Exception as e:
            errores += 1
            detalle_errores.append({
                "name": getattr(s, "name", None),
                "error": str(e),
            })
            db.session.rollback()
            continue

    db.session.commit()

    return {
        "modo": "insert",
        "mensaje": "Inserción de documentos soporte desde staging finalizada.",
        "cliente": idcliente,
        "fecha_desde": fecha_desde.isoformat(),
        "candidatos": len(candidatos),
        "insertadas": insertadas,
        "items_insertados": items_insertados,
        "omitidas": omitidas,
        "errores": errores,
        "detalle_errores": detalle_errores[:20],
    }