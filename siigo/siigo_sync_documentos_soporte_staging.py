import requests
from datetime import datetime
from decimal import Decimal, InvalidOperation

from models import (
    db,
    SiigoCredencial,
    SiigoProveedor,
    Cliente,
    SiigoDocumentoSoporteApiStaging,
)
from utils import _siigo_auth_json_for_client, _siigo_headers_bearer


def _to_decimal(value):
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None


def _to_int(value):
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _parse_date(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value).replace("Z", "")).date()
    except Exception:
        try:
            return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
        except Exception:
            return None


def _parse_datetime(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value).replace("Z", ""))
    except Exception:
        return None


def _extract_results(data):
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return data.get("results")

        if isinstance(data.get("data"), dict) and isinstance(data["data"].get("results"), list):
            return data["data"].get("results")

        if isinstance(data.get("data"), list):
            return data.get("data")

    if isinstance(data, list):
        return data

    return []


def _get_total_results(data):
    if not isinstance(data, dict):
        return None

    pagination = data.get("pagination")
    if isinstance(pagination, dict):
        return pagination.get("total_results")

    nested_data = data.get("data")
    if isinstance(nested_data, dict):
        pagination = nested_data.get("pagination")
        if isinstance(pagination, dict):
            return pagination.get("total_results")

    return None


def _get_retention_total(doc):
    retentions = doc.get("retentions") or []
    total = Decimal("0")

    if not isinstance(retentions, list):
        return total

    for r in retentions:
        if isinstance(r, dict):
            value = _to_decimal(r.get("value"))
            if value is not None:
                total += value

    return total


def _get_payment_value(doc):
    payments = doc.get("payments") or []
    total = Decimal("0")

    if not isinstance(payments, list):
        return None

    for p in payments:
        if isinstance(p, dict):
            value = _to_decimal(p.get("value"))
            if value is not None:
                total += value

    return total


def _get_first_due_date(doc):
    payments = doc.get("payments") or []

    if isinstance(payments, list) and payments:
        first = payments[0]
        if isinstance(first, dict):
            return _parse_date(first.get("due_date"))

    return None


def _build_factura_proveedor(doc):
    supplier_receipt = doc.get("supplier_receipt_number") or {}

    if not isinstance(supplier_receipt, dict):
        return None

    prefix = supplier_receipt.get("prefix")
    number = supplier_receipt.get("number")

    if prefix and number:
        return f"{prefix}-{number}"

    if number:
        return str(number)

    return None


def _get_supplier_name(idcliente, identificacion):
    if not identificacion:
        return None

    return db.session.execute(
        db.select(SiigoProveedor.nombre).where(
            SiigoProveedor.idcliente == idcliente,
            SiigoProveedor.identificacion == str(identificacion)
        ).limit(1)
    ).scalar()


def sync_documentos_soporte_staging_desde_siigo(
    idcliente: int,
    batch_size: int = 50,
    max_pages: int | None = None,
):
    cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
    cliente = Cliente.query.get(idcliente)

    if not cfg:
        return {"error": "Credenciales Siigo no configuradas"}

    auth_data = _siigo_auth_json_for_client(cfg)
    if not isinstance(auth_data, dict):
        return {
            "error": "Respuesta inesperada del auth de Siigo",
            "detalle": str(auth_data),
        }

    token = auth_data.get("access_token")
    if not token:
        return {
            "error": "No se obtuvo access_token",
            "detalle": auth_data,
        }

    headers = _siigo_headers_bearer(token)
    base_url = cfg.base_url.rstrip("/")

    nuevas = 0
    actualizadas = 0
    errores = 0
    omitidas = 0

    page = 1
    total_results_siigo = None

    while True:
        if max_pages and page > max_pages:
            break

        url = f"{base_url}/v1/purchase-support-documents?page_size={batch_size}&page={page}"
        print(f"[DS-STAGING] Consultando página {page}: {url}")

        r = requests.get(url, headers=headers, timeout=90)

        try:
            data = r.json()
        except ValueError:
            db.session.rollback()
            return {
                "error": f"Respuesta no JSON consultando documentos soporte. HTTP {r.status_code}",
                "detalle": r.text,
                "url": url,
            }

        if r.status_code != 200:
            db.session.rollback()
            return {
                "error": f"Error HTTP {r.status_code} consultando documentos soporte",
                "detalle": data,
                "url": url,
            }

        if total_results_siigo is None:
            total_results_siigo = _get_total_results(data)

        docs = _extract_results(data)

        print(f"[DS-STAGING] Documentos recibidos página {page}: {len(docs)}")

        if not docs:
            break

        for doc in docs:
            try:
                siigo_id = doc.get("id")
                name = doc.get("name")

                if not siigo_id or not name:
                    omitidas += 1
                    print(f"[DS-STAGING] Documento omitido por falta de id/name: {doc}")
                    continue

                supplier = doc.get("supplier") or {}
                supplier_receipt = doc.get("supplier_receipt_number") or {}
                document = doc.get("document") or {}
                stamp = doc.get("stamp") or {}
                metadata = doc.get("metadata") or {}

                proveedor_identificacion = None
                proveedor_siigo_id = None

                if isinstance(supplier, dict):
                    proveedor_identificacion = supplier.get("identification")
                    proveedor_siigo_id = supplier.get("id")

                proveedor_nombre = _get_supplier_name(idcliente, proveedor_identificacion)

                factura_proveedor = _build_factura_proveedor(doc)

                vencimiento = _get_first_due_date(doc)
                payment_value = _get_payment_value(doc)
                retentions_total = _get_retention_total(doc)

                items = doc.get("items") or []
                items_count = len(items) if isinstance(items, list) else 0

                existente = SiigoDocumentoSoporteApiStaging.query.filter_by(
                    idcliente=idcliente,
                    name=name
                ).first()

                if not existente:
                    existente = SiigoDocumentoSoporteApiStaging(
                        idcliente=idcliente,
                        siigo_id=siigo_id,
                        name=name,
                    )
                    db.session.add(existente)
                    nuevas += 1
                else:
                    actualizadas += 1

                existente.siigo_id = siigo_id
                existente.number = _to_int(doc.get("number"))
                existente.document_id = _to_int(document.get("id")) if isinstance(document, dict) else None

                existente.fecha = _parse_date(doc.get("date"))
                existente.vencimiento = vencimiento

                existente.proveedor_siigo_id = proveedor_siigo_id
                existente.proveedor_identificacion = (
                    str(proveedor_identificacion) if proveedor_identificacion else None
                )
                existente.proveedor_nombre = proveedor_nombre

                existente.cost_center = _to_int(doc.get("cost_center"))

                existente.total = _to_decimal(doc.get("total"))
                existente.balance = _to_decimal(doc.get("balance"))
                existente.payment_value = payment_value

                existente.supplier_receipt_prefix = (
                    supplier_receipt.get("prefix") if isinstance(supplier_receipt, dict) else None
                )
                existente.supplier_receipt_number = (
                    str(supplier_receipt.get("number")) if isinstance(supplier_receipt, dict) and supplier_receipt.get("number") is not None else None
                )
                existente.factura_proveedor = factura_proveedor

                existente.stamp_status = (
                    stamp.get("status") if isinstance(stamp, dict) else None
                )
                existente.cuds = (
                    stamp.get("cuds") if isinstance(stamp, dict) else None
                )

                existente.items_count = items_count
                existente.retentions_total = retentions_total

                existente.raw_json = doc
                existente.created_siigo = _parse_datetime(metadata.get("created"))

            except Exception as e:
                errores += 1
                print(f"[DS-STAGING] Error procesando documento: {e}")

        db.session.commit()

        page += 1

    return {
        "mensaje": "Sincronización staging de documentos soporte finalizada.",
        "cliente": idcliente,
        "nuevas": nuevas,
        "actualizadas": actualizadas,
        "omitidas": omitidas,
        "errores": errores,
        "total_procesadas": nuevas + actualizadas,
        "total_results_siigo": total_results_siigo,
    }