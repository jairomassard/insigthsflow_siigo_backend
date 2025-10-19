# backend/siigo/siigo_sync_refactor.py
# Sincronización Siigo: modo ligero (listado) y modo detallado (enriquecimiento por lotes).
# - Usa Decimal para todos los montos (evita Decimal vs float).
# - Reintentos/backoff en requests.
# - En deep=True solo trae detalle de un lote de facturas que lo necesitan.

import os
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

import requests
from cryptography.fernet import Fernet, InvalidToken
from decimal import Decimal

from models import db, Cliente, SiigoCredencial, SiigoFactura, SiigoFacturaItem

# -----------------------------
# Config
# -----------------------------
PARTNER_ID   = os.getenv("SIIGO_PARTNER_ID", "ProjectManagerApp")
PAGE_SIZE    = int(os.getenv("SIIGO_PAGE_SIZE", "100"))
READ_TIMEOUT = int(os.getenv("SIIGO_READ_TIMEOUT", "90"))
MAX_RETRIES  = int(os.getenv("SIIGO_MAX_RETRIES", "5"))
BASE_BACKOFF = float(os.getenv("SIIGO_BASE_BACKOFF", "0.6"))

# -----------------------------
# Crypto local (evita import circular con app.py)
# -----------------------------
FERNET_KEY = os.environ.get("APP_CRYPTO_KEY")
fernet = Fernet(FERNET_KEY) if FERNET_KEY else None

def dec_local(b: Optional[bytes]) -> Optional[str]:
    if b is None:
        return None
    if not fernet:
        try:
            return b.decode()
        except Exception:
            return None
    try:
        return fernet.decrypt(b).decode()
    except InvalidToken:
        return None

# -----------------------------
# Utilidades
# -----------------------------
class SiigoError(Exception):
    pass

def _headers_json() -> Dict[str, str]:
    return {"Content-Type": "application/json", "Partner-Id": PARTNER_ID}

def _headers_bearer(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Partner-Id": PARTNER_ID}

def _str(v) -> str:
    try:
        return (v or "").strip()
    except Exception:
        return ""

# --- Helpers Decimal (todo monto con Decimal) ---
DZERO = Decimal("0")
DONE  = Decimal("1")

def _d(v, default: Decimal = DZERO) -> Decimal:
    """Convierte a Decimal de forma segura."""
    try:
        if v is None or v == "":
            return default
        return Decimal(str(v))
    except Exception:
        return default

def _maybe_dec(v) -> Decimal:
    return v if isinstance(v, Decimal) else _d(v)

def _parse_seller(seller_val):
    """Devuelve (seller_name, seller_id_int_or_None) robusto."""
    if isinstance(seller_val, dict):
        name = _str(seller_val.get("name") or seller_val.get("full_name") or seller_val.get("display_name"))
        sid = seller_val.get("id")
        try:
            sid = int(sid) if sid is not None and str(sid).isdigit() else None
        except Exception:
            sid = None
        return name, sid
    if isinstance(seller_val, (int, float)):
        return "", int(seller_val)
    if isinstance(seller_val, str) and seller_val.isdigit():
        return "", int(seller_val)
    return "", None

def _safe_items_list(raw) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: List[Dict[str, Any]] = []
    for it in raw:
        if isinstance(it, dict):
            out.append(it)
    return out

def _sleep_backoff(attempt: int):
    delay = BASE_BACKOFF * (2 ** (attempt - 1))
    delay = min(delay, 8.0)
    time.sleep(delay + (0.05 * attempt))

def _should_retry(status: Optional[int], exc: Optional[Exception]) -> bool:
    if exc is not None:
        return True
    if status is None:
        return True
    return status in (429, 500, 502, 503, 504)

def _request_with_retries(method: str, url: str, headers: dict, **kwargs) -> requests.Response:
    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.request(method, url, headers=headers, timeout=READ_TIMEOUT, **kwargs)
            if not _should_retry(resp.status_code, None):
                return resp
            if attempt < MAX_RETRIES:
                _sleep_backoff(attempt)
                continue
            return resp
        except (requests.Timeout, requests.ConnectionError) as e:
            last_exc = e
            if attempt < MAX_RETRIES:
                _sleep_backoff(attempt)
                continue
            raise
    if last_exc:
        raise last_exc
    raise RuntimeError("Error desconocido en _request_with_retries")


# -----------------------------
# Autenticación y descarga
# -----------------------------
def siigo_auth_json(base_url: str, username: str, access_key: str) -> Dict[str, Any]:
    """Auth oficial: POST JSON a /auth o /v1/auth."""
    payload = {"username": username, "access_key": access_key}
    for path in ("/auth", "/v1/auth"):
        url = f"{base_url.rstrip('/')}{path}"
        r = _request_with_retries("POST", url, headers=_headers_json(), json=payload)
        if r.status_code == 200:
            return r.json() or {}
        if r.status_code == 404:
            continue
        raise SiigoError(f"Auth {r.status_code}: {r.text}")
    raise SiigoError("No se encontró endpoint de auth")

def fetch_all_invoices(base_url: str, token: str, page_size: int = PAGE_SIZE) -> List[Dict[str, Any]]:
    """Pagina /v1/invoices (ligero)."""
    results: List[Dict[str, Any]] = []
    page = 1
    while True:
        url = f"{base_url.rstrip('/')}/v1/invoices?page={page}&page_size={page_size}"
        r = _request_with_retries("GET", url, headers=_headers_bearer(token))
        if r.status_code != 200:
            raise SiigoError(f"Invoices {r.status_code}: {r.text}")
        data = r.json() or {}
        items = data.get("results") or []
        if not isinstance(items, list):
            raise SiigoError("Respuesta de /v1/invoices no es una lista en 'results'.")
        results.extend(items)
        next_href = ((data.get("_links") or {}).get("next") or {}).get("href")
        if not next_href or len(items) < page_size:
            break
        page += 1
    return results

def _fetch_invoice_detail_safe(base_url: str, token: str, invoice_id_or_uuid: str) -> dict:
    """Trae detalle por id/uuid; si falla, intenta por name."""
    url = f"{base_url.rstrip('/')}/v1/invoices/{invoice_id_or_uuid}"
    r = _request_with_retries("GET", url, headers=_headers_bearer(token))
    if r.status_code != 200:
        alt_url = f"{base_url.rstrip('/')}/v1/invoices?name={invoice_id_or_uuid}"
        r2 = _request_with_retries("GET", alt_url, headers=_headers_bearer(token))
        if r2.status_code == 200:
            payload = r2.json() or {}
            results = payload.get("results") or []
            if results:
                return results[0]
        raise SiigoError(f"Invoice detail {r.status_code}: {r.text}")
    return r.json() or {}

# -----------------------------
# Criterio de enriquecimiento
# -----------------------------
def _needs_enrichment(f: SiigoFactura) -> bool:
    return (
        f.subtotal is None
        and f.impuestos_total is None
        and f.descuentos_total is None
        and f.pagos_total is None
        and f.moneda is None
    )

# -----------------------------
# Sync principal (reemplazo)
# -----------------------------
def sync_facturas_desde_siigo(
    idcliente: int,
    deep: bool = False,
    batch_size: int = 50,
    only_missing: bool = True,
    since: Optional[str] = None,
) -> str:
    cliente = Cliente.query.filter_by(idcliente=idcliente).first()
    if not cliente:
        raise RuntimeError("Cliente no encontrado")

    cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
    if not cred or not cred.client_id or not cred.client_secret or not cred.base_url:
        raise RuntimeError("Credenciales de Siigo no configuradas")

    access_key = dec_local(cred.client_secret)
    if not access_key:
        raise RuntimeError("No se pudo desencriptar el Access Key")
    token_data = siigo_auth_json(base_url=cred.base_url, username=cred.client_id, access_key=access_key)
    token = token_data["access_token"]

    # -----------------------------
    # Helpers locales (suman Decimal)
    # -----------------------------
    def sum_subtotal_from_items(items: List[Dict[str, Any]]) -> Decimal:
        return sum((_d(it.get("price"), DZERO) * _d(it.get("quantity"), DONE)) for it in items)

    def sum_iva_from_items(items: List[Dict[str, Any]]) -> Decimal:
        total_iva = DZERO
        for it in items:
            taxes = it.get("taxes") or []
            if not isinstance(taxes, list):
                continue
            for tx in taxes:
                if not isinstance(tx, dict):
                    continue
                ttype = _str(tx.get("type")).upper()
                tname = _str(tx.get("name")).upper()
                if "IVA" in ttype or "IVA" in tname:
                    total_iva += _d(tx.get("value"), DZERO)
        return total_iva

    def sum_payments_value(payments: Any) -> Decimal:
        if not isinstance(payments, list):
            return DZERO
        return sum(_d(p.get("value"), DZERO) for p in payments if isinstance(p, dict))

    # =============================
    # MODO LIGERO (deep=False)
    # =============================
    if not deep:
        nuevas = 0
        actualizadas = 0

        # 1) Listado paginado
        invoices_list = fetch_all_invoices(base_url=cred.base_url, token=token)

        # 2) Filtro opcional por fecha (since=YYYY-MM-DD)
        if since:
            try:
                since_dt = datetime.fromisoformat(since).date()
                filtered = []
                for it in invoices_list:
                    try:
                        d = it.get("date")
                        it_date = datetime.fromisoformat(str(d)).date() if d else None
                        if it_date and it_date >= since_dt:
                            filtered.append(it)
                    except Exception:
                        # Si no se puede parsear, lo dejamos pasar por seguridad
                        filtered.append(it)
                invoices_list = filtered
            except Exception:
                pass

        # 3) Upsert básico en siigo_facturas
        for it in invoices_list:
            try:
                inv_id   = _str(it.get("id"))
                name     = _str(it.get("name"))     # p.ej. "FV-2-1689"
                date     = _str(it.get("date"))
                status   = _str(it.get("status"))
                total    = _d(it.get("total"), DZERO)
                balance  = _d(it.get("balance"), DZERO)
                public   = _str(it.get("public_url"))

                customer = it.get("customer") or {}
                cname    = customer.get("name")
                if isinstance(cname, list):
                    cname = cname[0] if cname else ""
                customer_name  = _str(cname)
                customer_id    = _str(customer.get("id"))
                customer_ident = _str(customer.get("identification"))

                seller_name, seller_id_val = _parse_seller(it.get("seller"))

                # Buscar primero por nombre de factura (idfactura), luego por uuid
                f = None
                if name:
                    f = SiigoFactura.query.filter_by(idcliente=idcliente, idfactura=name).first()
                if not f and inv_id:
                    f = SiigoFactura.query.filter_by(idcliente=idcliente, siigo_uuid=inv_id).first()

                if not f:
                    # Crear nuevo registro "ligero"
                    f = SiigoFactura(
                        idcliente=idcliente,
                        idfactura=name or None,
                        siigo_uuid=inv_id or None,
                        fecha=(date or None),
                        estado=status or None,
                        cliente_nombre=customer_name or None,
                        customer_id=customer_id or None,
                        customer_identificacion=customer_ident or None,
                        vendedor=seller_name or None,
                        seller_id=seller_id_val,
                        public_url=public or None,
                        total=(total if total != DZERO else None),
                        saldo=(balance if balance != DZERO else DZERO),
                    )
                    db.session.add(f)
                    nuevas += 1
                else:
                    # Actualizar campos básicos si cambiaron
                    changed = False
                    if date and f.fecha != date:
                        f.fecha = date; changed = True
                    if status and f.estado != status:
                        f.estado = status; changed = True
                    if (total != DZERO) and (f.total != total):
                        f.total = total; changed = True
                    if (balance is not None) and (f.saldo != balance):
                        f.saldo = balance; changed = True
                    if public and f.public_url != public:
                        f.public_url = public; changed = True
                    if customer_name and (f.cliente_nombre or "") != customer_name:
                        f.cliente_nombre = customer_name; changed = True
                    if customer_id and (f.customer_id or "") != customer_id:
                        f.customer_id = customer_id; changed = True
                    if customer_ident and (f.customer_identificacion or "") != customer_ident:
                        f.customer_identificacion = customer_ident; changed = True
                    if seller_id_val and f.seller_id != seller_id_val:
                        f.seller_id = seller_id_val; changed = True
                    if seller_name and (f.vendedor or "") != seller_name:
                        f.vendedor = seller_name; changed = True
                    if changed:
                        actualizadas += 1

            except Exception:
                # Evita que un registro malformado tumbe el lote
                continue

        db.session.commit()
        return f"Ligero: {nuevas} nuevas, {actualizadas} actualizadas, total procesadas {len(invoices_list)}."

    # =============================
    # MODO DETALLADO (deep=True)
    # =============================
    q = SiigoFactura.query.filter_by(idcliente=idcliente)
    if only_missing:
        q = q.filter(
            (SiigoFactura.subtotal.is_(None)) |
            (SiigoFactura.estado_pago.is_(None)) |
            (SiigoFactura.estado_pago != 'pagada') |
            (SiigoFactura.pagos_total == None) |
            (SiigoFactura.saldo > DZERO)
        )
    if since:
        try:
            since_dt = datetime.fromisoformat(since).date()
            q = q.filter(SiigoFactura.fecha >= since_dt)
        except Exception:
            pass

    objetivos: List[SiigoFactura] = (
        q.order_by(SiigoFactura.fecha.desc(), SiigoFactura.id.desc())
         .limit(max(1, int(batch_size)))
         .all()
    )

    if not objetivos:
        return "No hay facturas pendientes de enriquecer."

    enriquecidas = 0
    for f in objetivos:
        inv_id = f.siigo_uuid or f.idfactura
        try:
            detalle = _fetch_invoice_detail_safe(cred.base_url, token, inv_id)
        except Exception:
            continue

        f.siigo_uuid = _str(detalle.get("id") or f.siigo_uuid)

        if detalle.get("date"):
            f.fecha = detalle.get("date")
        f.estado = _str(detalle.get("status") or f.estado or "Emitida")

        customer_raw = detalle.get("customer") or {}
        cname = customer_raw.get("name")
        if isinstance(cname, list):
            cname = cname[0] if cname else ""
        f.cliente_nombre = _str(cname or f.cliente_nombre or "")
        f.customer_id = _str(customer_raw.get("id") or f.customer_id or "")
        f.customer_identificacion = _str(customer_raw.get("identification") or f.customer_identificacion or "")

        seller_name, seller_id_val = _parse_seller(detalle.get("seller"))
        f.seller_id = seller_id_val or f.seller_id
        if seller_name:
            f.vendedor = seller_name

        f.public_url = _str(detalle.get("public_url"))
        f.cost_center = detalle.get("cost_center")

        retenciones_raw = detalle.get("retentions") or []
        retenciones_clean = []
        for r in retenciones_raw:
            if isinstance(r, dict):
                retenciones_clean.append({
                    "type": _str(r.get("type")),
                    "percentage": float(_d(r.get("percentage"), DZERO)),
                    "value": float(_d(r.get("value"), DZERO))
                })
        f.retenciones = retenciones_clean or None

        items_detalle = _safe_items_list(detalle.get("items"))
        payments = detalle.get("payments") or []

        subtotal = sum_subtotal_from_items(items_detalle)
        iva_total = sum_iva_from_items(items_detalle)
        descuentos_total = DZERO
        pagos_total = sum_payments_value(payments)

        total_det = _d(detalle.get("total"), None)
        if total_det is None:
            total_det = subtotal + iva_total - descuentos_total

        balance = _d(detalle.get("balance"), None)
        if balance is None:
            balance = total_det - pagos_total
            if balance < DZERO:
                balance = DZERO

        currency = _str(detalle.get("currency"))
        estado_pago = "pendiente"
        if pagos_total > DZERO and balance == DZERO:
            estado_pago = "pagada"
        elif pagos_total > DZERO and balance > DZERO:
            estado_pago = "parcial"

        observ = _str(detalle.get("observations"))
        meta = detalle.get("metadata") or {}
        created = _str(meta.get("created"))
        updated = _str(meta.get("updated"))

        f.subtotal = subtotal if subtotal != DZERO else (f.subtotal or None)
        f.impuestos_total = iva_total if iva_total != DZERO else (f.impuestos_total or None)
        f.descuentos_total = descuentos_total if descuentos_total != DZERO else (f.descuentos_total or None)
        f.pagos_total = pagos_total if pagos_total != DZERO else (f.pagos_total or None)
        f.total = total_det if total_det is not None else (f.total or None)
        f.saldo = balance if balance is not None else (f.saldo or DZERO)
        f.saldo_calculado = (f.total or DZERO) - (f.pagos_total or DZERO)
        if f.saldo_calculado < DZERO:
            f.saldo_calculado = DZERO
        f.estado_pago = estado_pago or f.estado_pago
        f.moneda = currency or f.moneda
        f.medio_pago = _str((payments[0].get("name")) if (isinstance(payments, list) and payments and isinstance(payments[0], dict)) else (f.medio_pago or None))
        f.observaciones = observ or f.observaciones
        f.metadata_created = (datetime.fromisoformat(created.replace("Z", "+00:00")) if created else f.metadata_created)
        f.metadata_updated = (datetime.fromisoformat(updated.replace("Z", "+00:00")) if updated else f.metadata_updated)

        # Ítems detallados: borra e inserta
        if items_detalle:
            SiigoFacturaItem.query.filter_by(factura_id=f.id).delete()
            for it in items_detalle:
                taxes_it = it.get("taxes") or []
                iva_pct = None
                iva_val = DZERO
                retenciones_item_clean = []

                if isinstance(taxes_it, list):
                    for t in taxes_it:
                        if isinstance(t, dict):
                            ttype = _str(t.get("type"))
                            perc = float(_d(t.get("percentage"), DZERO))
                            val = float(_d(t.get("value"), DZERO))
                            retenciones_item_clean.append({
                                "type": ttype,
                                "percentage": perc,
                                "value": val,
                            })
                            if "IVA" in ttype.upper():
                                iva_pct = perc
                                iva_val = _d(t.get("value"), DZERO)

                total_item = _d(it.get("total"), None)
                if total_item is None:
                    total_item = _d(it.get("price"), DZERO) * _d(it.get("quantity"), DONE)
                desc_val = _d(it.get("discount") or it.get("discounts"), DZERO)

                db.session.add(SiigoFacturaItem(
                    factura_id=f.id,
                    descripcion=_str(it.get("description")),
                    cantidad=_d(it.get("quantity"), DONE),
                    precio=_d(it.get("price"), DZERO),
                    impuestos=iva_val,
                    producto_id=_str((it.get("code") or it.get("id") or "")),
                    codigo=_str(it.get("code")),
                    sku=_str(it.get("sku")),
                    iva_porcentaje=(iva_pct if iva_pct != DZERO else None),
                    iva_valor=(iva_val if iva_val != DZERO else None),
                    descuento_valor=(desc_val if desc_val != DZERO else None),
                    total_item=total_item,
                    retenciones_item=retenciones_item_clean or None,
                ))

        enriquecidas += 1

    db.session.commit()
    return f"Detallado: {enriquecidas} facturas enriquecidas en este lote (máx {batch_size})."



def contar_facturas_pendientes(idcliente: int) -> int:
    return SiigoFactura.query.filter_by(idcliente=idcliente).filter(
        (SiigoFactura.subtotal.is_(None)) |
        (SiigoFactura.estado_pago != 'pagada') |
        (SiigoFactura.pagos_total == None) |
        (SiigoFactura.saldo > DZERO)
    ).count()
