# siigo_api.py
import base64
import time
import requests


class SiigoError(Exception):
    pass


def _clean_header_value(value: str | None) -> str:
    if value is None:
        return ""

    return str(value).strip().strip('"').strip("'")


def _partner_id_required(partner_id: str | None) -> str:
    partner_id = _clean_header_value(partner_id)

    if not partner_id:
        raise SiigoError(
            "Partner ID de Siigo no configurado. "
            "Debe enviarse explícitamente desde las credenciales del cliente."
        )

    return partner_id


def _headers_bearer(token: str, partner_id: str):
    partner_id = _partner_id_required(partner_id)

    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Partner-Id": partner_id,
    }


def _headers_basic(user: str, access_key: str, partner_id: str):
    partner_id = _partner_id_required(partner_id)
    basic = base64.b64encode(f"{user}:{access_key}".encode()).decode()

    return {
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Partner-Id": partner_id,
    }


def auth(base_url: str, user_api: str, access_key: str, partner_id: str) -> dict:
    """
    Devuelve dict con {access_token, token_type, expires_in}.

    Este helper ya no usa Partner ID global.
    El Partner ID debe venir desde las credenciales del cliente.
    """

    partner_id = _partner_id_required(partner_id)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Partner-Id": partner_id,
    }

    payload = {
        "username": user_api,
        "access_key": access_key,
    }

    for path in ("/auth", "/v1/auth"):
        url = f"{base_url.rstrip('/')}{path}"

        r = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=30,
        )

        if r.status_code in (200, 201):
            return r.json() or {}

        if r.status_code == 404:
            continue

        raise SiigoError(f"Auth {r.status_code}: {r.text}")

    raise SiigoError("No se encontró endpoint de auth")


def list_invoices(
    base_url: str,
    token: str,
    partner_id: str,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    """
    Devuelve payload de /v1/invoices.

    Este helper requiere Partner ID explícito.
    """

    url = f"{base_url.rstrip('/')}/v1/invoices?page={page}&page_size={page_size}"

    r = requests.get(
        url,
        headers=_headers_bearer(token, partner_id),
        timeout=60,
    )

    if r.status_code != 200:
        raise SiigoError(f"Invoices {r.status_code}: {r.text}")

    return r.json()