import os
import requests
from cryptography.fernet import Fernet, InvalidToken
from models import SiigoCredencial
from pytz import timezone, utc
from datetime import datetime

FERNET_KEY = os.environ.get("APP_CRYPTO_KEY")  # genera una vez y guárdala en .env
fernet = Fernet(FERNET_KEY) if FERNET_KEY else None

def dec(b: bytes | None) -> str | None:
    if b is None: return None
    if not fernet: return b.decode()
    try:
        return fernet.decrypt(b).decode()
    except InvalidToken:
        return None

def _siigo_headers_bearer(token: str):
    partner_id = os.getenv("SIIGO_PARTNER_ID", "ProjectManagerApp").strip() or "ProjectManagerApp"
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Partner-Id": partner_id,
    }

def _siigo_auth_json_for_client(cfg: SiigoCredencial) -> dict:
    base_url = (cfg.base_url or "").rstrip("/")
    auth_url = f"{base_url}/auth"

    username = cfg.client_id or ""
    access_key = dec(cfg.client_secret) or ""
    partner_id = os.getenv("SIIGO_PARTNER_ID", "ProjectManagerApp").strip() or "ProjectManagerApp"

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Partner-Id": partner_id,
    }
    payload = {"username": username, "access_key": access_key}

    try:
        r = requests.post(auth_url, headers=headers, json=payload, timeout=60)
        if r.status_code == 200:
            return r.json() or {}
        else:
            return {
                "error": f"Fallo autenticación Siigo",
                "status": r.status_code,
                "detalle": r.text,
                "endpoint": auth_url
            }
    except requests.RequestException as e:
        return {
            "error": "Excepción al llamar endpoint de autenticación Siigo",
            "detalle": str(e),
            "endpoint": auth_url
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
    Convierte una fecha local (según el cliente) a UTC.
    """
    if dt_local is None:
        return None
    tz = timezone(tz_str)
    if dt_local.tzinfo is None:
        dt_local = tz.localize(dt_local)
    return dt_local.astimezone(utc)

def siigo_date_to_utc(date_str: str, tz_str: str = "America/Bogota") -> datetime | None:
    """
    Convierte una fecha ISO 8601 (posiblemente sin zona horaria) a datetime en UTC.
    """
    if not date_str:
        return None

    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            # Si no tiene tzinfo, asumir zona local del cliente
            tz = timezone(tz_str)
            dt = tz.localize(dt)
        return dt.astimezone(utc)
    except Exception as e:
        print(f"[WARN] siigo_date_to_utc: Error al parsear '{date_str}': {e}")
        return None
