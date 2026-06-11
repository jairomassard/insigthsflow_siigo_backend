# siigo_api.py
import os, base64, time
import requests

PARTNER_ID = os.getenv("SIIGO_PARTNER_ID", "ProjectManagerApp")
SANDBOX = os.getenv("SIIGO_SANDBOX", "0") == "1"

class SiigoError(Exception):
    pass

def _headers_bearer(token: str):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Partner-Id": PARTNER_ID,
    }

def _headers_basic(user: str, access_key: str):
    basic = base64.b64encode(f"{user}:{access_key}".encode()).decode()
    return {
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/json",
        "Partner-Id": PARTNER_ID,
    }

def auth(base_url: str, user_api: str, access_key: str) -> dict:
    """
    Devuelve dict con {access_token, token_type, expires_in}
    """
    if SANDBOX:
        time.sleep(0.2)
        return {"access_token": "sandbox-token", "token_type": "bearer", "expires_in": 3600}

    headers = {
        "Content-Type": "application/json",
        "Partner-Id": PARTNER_ID,
    }
    payload = {
        "username": user_api,
        "access_key": access_key
    }

    for path in ("/auth", "/v1/auth"):
        url = f"{base_url.rstrip('/')}{path}"
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            continue
        raise SiigoError(f"Auth {r.status_code}: {r.text}")
    raise SiigoError("No se encontró endpoint de auth")



def list_invoices(base_url: str, token: str, page:int=1, page_size:int=50) -> dict:
    """
    Devuelve payload de /v1/invoices
    """
    if SANDBOX:
        # Mock mínimo con estructura realista
        return {
            "results":[
                {
                    "name":"FV-0001",
                    "date":"2025-09-05",
                    "metadata":{"created":"2025-09-05T10:11:12Z"},
                    "seller": {"id": 1, "name": "Vendedor Demo"},
                    "customer":{"id":"c-123","name":["Cliente Demo S.A.S."]},
                    "items":[{"description":"Producto A","quantity":2,"price":15000}]
                }
            ],
            "_links":{"next":{"href": None}}
        }

    url = f"{base_url.rstrip('/')}/v1/invoices?page={page}&page_size={page_size}"
    r = requests.get(url, headers=_headers_bearer(token), timeout=60)
    if r.status_code != 200:
        raise SiigoError(f"Invoices {r.status_code}: {r.text}")
    return r.json()
