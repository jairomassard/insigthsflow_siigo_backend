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


def _parse_fecha_desde(value):
    """
    Si viene fecha, la parsea.
    Si no viene fecha, retorna None para NO limitar por fecha.

    Esto es importante para InsightFlow como SaaS:
    - Algunos clientes querrán cargar todo su histórico disponible en Siigo.
    - Otros querrán empezar desde una fecha específica.
    - El filtro por fecha debe ser opcional, no quemado en código.
    """
    if not value:
        return None

    if isinstance(value, date):
        return value

    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
    except Exception:
        return None


def _fecha_to_json(value):
    return value.isoformat() if value else None


def _get_raw_items(raw_json):
    if not isinstance(raw_json, dict):
        return []

    items = raw_json.get("items") or []

    if not isinstance(items, list):
        return []

    return items


def _sum_items_total(raw_json):
    """
    Calcula el valor bruto desde los items.

    En Documento Soporte, el campo total de la API puede venir como valor neto
    después de retenciones. Para mantener consistencia con siigo_compras,
    el encabezado debe guardar el bruto del documento.

    Prioridad:
    - Sumar item.total si existe.
    - Si no existe, usar item.price * item.quantity.
    """
    total = Decimal("0")

    for item in _get_raw_items(raw_json):
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

    Nota:
    - No usamos retenciones como impuestos de item.
    - Las retenciones se usan para reconstruir el bruto si no se puede sumar items.
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
    Calcula el total bruto que debe quedar en siigo_compras.total.

    Prioridad:
    1. Suma raw_json.items.total.
    2. staging.total + staging.retentions_total.
    3. staging.total.

    Esto evita guardar como total el valor neto cuando Siigo descuenta retenciones.
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
    Inserta en siigo_compras únicamente Documentos Soporte nuevos
    provenientes de siigo_documentos_soporte_api_staging.

    Reglas productivas:
    - Solo documentos que NO existan ya en siigo_compras.
    - Solo stamp_status = Accepted.
    - Solo total > 0.
    - Solo items_count > 0.
    - Si fecha_desde viene informada, solo fecha >= fecha_desde.
    - No usa balance API como saldo definitivo.
    - Inserta saldo inicial igual al total bruto.
    - Luego sync-accounts-payable y cross-accounts-payable deben ajustar saldo/estado.
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
    )

    # Filtro opcional. Si fecha_desde es None, NO se limita por fecha.
    if fecha_desde:
        query = query.filter(SiigoDocumentoSoporteApiStaging.fecha >= fecha_desde)

    query = query.order_by(
        SiigoDocumentoSoporteApiStaging.fecha.asc(),
        SiigoDocumentoSoporteApiStaging.name.asc(),
    )

    if max_registros:
        query = query.limit(max_registros)

    candidatos = query.all()

    if dry_run:
        return {
            "modo": "dry_run",
            "mensaje": "Simulación finalizada. No se insertó información.",
            "cliente": idcliente,
            "fecha_desde": _fecha_to_json(fecha_desde),
            "candidatos": len(candidatos),
            "preview": [
                {
                    "name": s.name,
                    "fecha": _fecha_to_json(s.fecha),
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
            # Doble validación para evitar duplicados si otro proceso insertó antes.
            existe = SiigoCompra.query.filter_by(
                idcliente=idcliente,
                idcompra=s.name,
            ).first()

            if existe:
                omitidas += 1
                continue

            raw_json = s.raw_json or {}
            raw_items = _get_raw_items(raw_json)

            if not raw_items:
                omitidas += 1
                continue

            total_bruto = _calcular_total_bruto(s)

            if total_bruto is None or total_bruto <= 0:
                omitidas += 1
                continue

            retencion_total = _to_decimal(s.retentions_total, Decimal("0"))

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
                retencion_total=retencion_total,
            )

            db.session.add(compra)
            db.session.flush()

            for item in raw_items:
                if not isinstance(item, dict):
                    continue

                descripcion = item.get("description") or f"Documento soporte {s.name}"

                cantidad = _to_decimal(item.get("quantity"), Decimal("1"))

                # Seguimos la lógica de compras:
                # - precio = item.price si existe.
                # - si no existe, usamos item.total.
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

            db.session.commit()
            insertadas += 1

        except Exception as e:
            db.session.rollback()
            errores += 1
            detalle_errores.append({
                "name": getattr(s, "name", None),
                "error": str(e),
            })
            continue

    return {
        "modo": "insert",
        "mensaje": "Inserción de documentos soporte desde staging finalizada.",
        "cliente": idcliente,
        "fecha_desde": _fecha_to_json(fecha_desde),
        "candidatos": len(candidatos),
        "insertadas": insertadas,
        "items_insertados": items_insertados,
        "omitidas": omitidas,
        "errores": errores,
        "detalle_errores": detalle_errores[:20],
    }