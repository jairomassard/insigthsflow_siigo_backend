import os
import requests
from cryptography.fernet import Fernet, InvalidToken
from models import SiigoCredencial
from pytz import timezone, utc
from datetime import datetime


FERNET_KEY = os.environ.get("APP_CRYPTO_KEY")
fernet = Fernet(FERNET_KEY) if FERNET_KEY else None


def dec(b: bytes | None) -> str | None:
    if b is None:
        return None

    if not fernet:
        return b.decode()

    try:
        return fernet.decrypt(b).decode()
    except InvalidToken:
        return None


def _clean_header_value(value: str | None) -> str:
    """
    Limpia valores que puedan venir con espacios o comillas.
    Ejemplo:
    - ' InsightsFlow ' -> 'InsightsFlow'
    - '"InsightsFlow"' -> 'InsightsFlow'
    """
    if value is None:
        return ""

    return str(value).strip().strip('"').strip("'")


def _siigo_partner_id_for_client(cfg: SiigoCredencial | None = None) -> str:
    """
    Resuelve el Partner ID de Siigo para un cliente.

    Regla SaaS / multitenant:
    - El Partner ID debe venir desde siigo_credenciales.partner_id.
    - No usamos fallback global de Railway.
    - No usamos valores quemados como ProjectManagerApp.

    Si el cliente no tiene Partner ID configurado, se lanza error claro.
    """

    if cfg is None:
        raise ValueError(
            "Partner ID de Siigo no configurado: no se recibió la credencial del cliente."
        )

    partner_id = _clean_header_value(getattr(cfg, "partner_id", None))

    if not partner_id:
        raise ValueError(
            "Partner ID de Siigo no configurado para este cliente. "
            "Debe guardar el campo partner_id en siigo_credenciales."
        )

    return partner_id


def _siigo_headers_bearer(token: str, cfg: SiigoCredencial | None = None):
    """
    Headers para consumir endpoints protegidos de Siigo.

    Importante:
    - Requiere cfg para tomar el Partner ID del cliente.
    - Si no recibe cfg o cfg.partner_id está vacío, lanza error.
    """

    partner_id = _siigo_partner_id_for_client(cfg)

    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Partner-Id": partner_id,
    }


def _siigo_auth_json_for_client(cfg: SiigoCredencial) -> dict:
    """
    Autenticación oficial de Siigo usando:
    - username: cfg.client_id
    - access_key: cfg.client_secret desencriptado
    - Partner-Id: cfg.partner_id

    Retorna:
    - dict con access_token si funciona
    - dict con error si falla
    """

    base_url = (cfg.base_url or "").rstrip("/")
    auth_url = f"{base_url}/auth"

    username = cfg.client_id or ""
    access_key = dec(cfg.client_secret) or ""

    try:
        partner_id = _siigo_partner_id_for_client(cfg)
    except ValueError as e:
        return {
            "error": "Partner ID no configurado",
            "detalle": str(e),
            "endpoint": auth_url,
        }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Partner-Id": partner_id,
    }

    payload = {
        "username": username,
        "access_key": access_key,
    }

    try:
        r = requests.post(
            auth_url,
            headers=headers,
            json=payload,
            timeout=60,
        )

        if r.status_code in (200, 201):
            return r.json() or {}

        return {
            "error": "Fallo autenticación Siigo",
            "status": r.status_code,
            "detalle": r.text,
            "endpoint": auth_url,
            "partner_id_usado": partner_id,
        }

    except requests.RequestException as e:
        return {
            "error": "Excepción al llamar endpoint de autenticación Siigo",
            "detalle": str(e),
            "endpoint": auth_url,
            "partner_id_usado": partner_id,
        }


def utc_to_local(dt_utc: datetime, tz_str: str) -> datetime:
    """
    Convierte una fecha UTC a hora local usando la zona horaria del cliente.
    """
    if dt_utc is None:
        return None

    if dt_utc.tzinfo is None:
        dt_utc = utc.localize(dt_utc)

    return dt_utc.astimezone(timezone(tz_str))


def local_to_utc(dt_local: datetime, tz_str: str) -> datetime:
    """
    Convierte una fecha local, según zona horaria del cliente, a UTC.
    """
    if dt_local is None:
        return None

    tz = timezone(tz_str)

    if dt_local.tzinfo is None:
        dt_local = tz.localize(dt_local)

    return dt_local.astimezone(utc)


def siigo_date_to_utc(date_str: str, tz_str: str = "America/Bogota") -> datetime | None:
    """
    Convierte una fecha ISO 8601, posiblemente sin zona horaria, a datetime UTC.
    """
    if not date_str:
        return None

    try:
        dt = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))

        if dt.tzinfo is None:
            tz = timezone(tz_str)
            dt = tz.localize(dt)

        return dt.astimezone(utc)

    except Exception as e:
        print(f"[WARN] siigo_date_to_utc: Error al parsear '{date_str}': {e}")
        return None