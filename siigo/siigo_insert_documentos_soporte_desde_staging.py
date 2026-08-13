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
    Guarda IVA del item si viene en la API.

    FIX (2026-08-13): antes sumaba TODAS las entradas de `taxes` sin mirar el
    tipo (a pesar de que el docstring ya decia "no usamos retenciones como
    impuestos de item") - mismo bug que ya se habia corregido en
    siigo_sync_compras.py el 2026-07-23 para facturas de compra, pero nunca
    se replico aca. Confirmado con dato real: DS-1-1793 (Binaria) tiene un
    item con taxes=[Retefuente 4%, $66.000] y CERO IVA, y quedaba guardado
    como impuestos=$66.000 (mostrado como IVA en el reporte). Ahora solo se
    suman las entradas de tipo IVA, igual que en compras y ventas.
    """
    taxes = item.get("taxes") if isinstance(item, dict) else None
    total = Decimal("0")

    if not isinstance(taxes, list):
        return total

    for tax in taxes:
        if not isinstance(tax, dict):
            continue

        ttype = str(tax.get("type") or "").upper()
        tname = str(tax.get("name") or "").upper()

        if "IVA" in ttype or "IVA" in tname:
            total += _to_decimal(tax.get("value"), Decimal("0"))

    return total


def _retenciones_item(item):
    """
    Retefuente/ReteIVA que vienen mezcladas con el IVA en items[].taxes[] -
    ver misma nota en _sum_item_taxes(). Puramente informativo para el modal,
    mismo shape que siigo_sync_compras.py usa para facturas de compra.
    """
    taxes = item.get("taxes") if isinstance(item, dict) else None

    if not isinstance(taxes, list):
        return []

    resultado = []
    for tax in taxes:
        if not isinstance(tax, dict):
            continue

        ttype = str(tax.get("type") or "").upper()
        tname = str(tax.get("name") or "").upper()

        if "IVA" in ttype or "IVA" in tname:
            continue

        resultado.append({
            "type": tax.get("name") or tax.get("type") or "Retención",
            "percentage": tax.get("percentage"),
            "value": tax.get("value"),
        })

    return resultado


def _retenciones_compra(raw_json):
    """
    Retenciones a nivel de documento (ej. ReteICA) - viene del arreglo
    `retentions` del raw_json ya guardado en staging. Puramente informativo,
    NO reemplaza retencion_total (que sigue viniendo de
    staging.retentions_total y es lo único que afecta saldo/estado de pago).
    """
    retentions_raw = raw_json.get("retentions") if isinstance(raw_json, dict) else None

    if not isinstance(retentions_raw, list):
        return []

    resultado = []
    for r in retentions_raw:
        if not isinstance(r, dict):
            continue

        resultado.append({
            "type": r.get("name") or str(r.get("type") or "Retención"),
            "percentage": r.get("percentage"),
            "value": r.get("value"),
        })

    return resultado


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
                retenciones=_retenciones_compra(raw_json) or None,
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
                    retenciones_item=_retenciones_item(item) or None,
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


def backfill_retenciones_documentos_soporte(idcliente: int, dry_run: bool = False):
    """
    Recalcula retenciones/retenciones_item e impuestos (fix IVA-only, ver
    _sum_item_taxes) para los Documento Soporte que YA están en siigo_compras,
    releyendo el raw_json que ya está cacheado en
    siigo_documentos_soporte_api_staging (NO llama a la API de Siigo).

    Alcance: solo toca retenciones/retenciones_item (columnas nuevas,
    NULL -> pobladas) e impuestos por item (corrige valores ya inflados por
    el bug de _sum_item_taxes). NO toca total/saldo/retencion_total/estado de
    pago - esos siguen dependiendo únicamente de lo que ya calculaba
    insertar_documentos_soporte_desde_staging al momento de insertar.
    """
    compras = (
        db.session.query(SiigoCompra, SiigoDocumentoSoporteApiStaging)
        .join(
            SiigoDocumentoSoporteApiStaging,
            and_(
                SiigoDocumentoSoporteApiStaging.idcliente == SiigoCompra.idcliente,
                SiigoDocumentoSoporteApiStaging.name == SiigoCompra.idcompra,
            ),
        )
        .filter(SiigoCompra.idcliente == idcliente)
        .filter(SiigoCompra.idcompra.ilike("DS-%"))
        .all()
    )

    actualizadas_compra = 0
    actualizadas_items = 0
    sin_raw_json = 0
    items_desalineados = 0
    preview = []

    for compra, staging in compras:
        raw_json = staging.raw_json or {}
        raw_items = _get_raw_items(raw_json)

        if not raw_items:
            sin_raw_json += 1
            continue

        nuevas_retenciones_compra = _retenciones_compra(raw_json) or None

        if dry_run:
            if len(preview) < 30:
                preview.append({
                    "idcompra": compra.idcompra,
                    "retenciones_compra_antes": compra.retenciones,
                    "retenciones_compra_despues": nuevas_retenciones_compra,
                })
            continue

        if compra.retenciones != nuevas_retenciones_compra:
            compra.retenciones = nuevas_retenciones_compra
            actualizadas_compra += 1

        # order_by(id): garantiza el mismo orden en que se insertaron desde
        # raw_items originalmente en insertar_documentos_soporte_desde_staging
        # (ahi se itera raw_items en orden y cada item se agrega con id
        # autoincremental) - necesario para el zip() de abajo, no se puede
        # asumir el orden de un SELECT sin ORDER BY explicito.
        items_db = (
            SiigoCompraItem.query
            .filter_by(compra_id=compra.id)
            .order_by(SiigoCompraItem.id)
            .all()
        )

        if len(items_db) != len(raw_items):
            # Desalineado (ej. algun item se filtro distinto al insertar) -
            # no arriesgar un emparejamiento incorrecto por posicion.
            items_desalineados += 1
            continue

        for item_db, raw_item in zip(items_db, raw_items):
            if not isinstance(raw_item, dict):
                continue

            nuevo_impuestos = _sum_item_taxes(raw_item)
            nuevas_retenciones_item = _retenciones_item(raw_item) or None

            cambio = (
                item_db.impuestos != nuevo_impuestos
                or item_db.retenciones_item != nuevas_retenciones_item
            )

            if cambio:
                item_db.impuestos = nuevo_impuestos
                item_db.retenciones_item = nuevas_retenciones_item
                actualizadas_items += 1

    if dry_run:
        return {
            "modo": "dry_run",
            "cliente": idcliente,
            "documentos_soporte_encontrados": len(compras),
            "sin_raw_json": sin_raw_json,
            "preview": preview,
        }

    db.session.commit()

    return {
        "modo": "backfill",
        "cliente": idcliente,
        "documentos_soporte_encontrados": len(compras),
        "sin_raw_json": sin_raw_json,
        "items_desalineados": items_desalineados,
        "compras_actualizadas": actualizadas_compra,
        "items_actualizados": actualizadas_items,
    }