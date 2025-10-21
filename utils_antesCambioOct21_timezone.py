import os
import requests
from cryptography.fernet import Fernet, InvalidToken
from models import SiigoCredencial

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
