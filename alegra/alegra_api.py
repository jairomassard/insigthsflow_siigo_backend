"""
Cliente HTTP de bajo nivel para la API de Alegra. Analogo a siigo_api.py, pero
sin flujo de auth por token: Alegra usa Basic Auth directo (email + API token)
en cada request, confirmado en la Fase 0 del Plan Maestro.
"""

import base64
import time
import requests

ALEGRA_BASE_URL_DEFAULT = "https://api.alegra.com/api/v1"

# Confirmado en Fase 0 (Postman, 2026-07-07): varios endpoints de listado
# (invoices, sellers, etc.) tienen tope de 30 por pagina.
DEFAULT_LIMIT = 30

# CONFIRMADO 2026-07-08 contra Importadora NGC (cuenta de alto volumen):
# /journals e /invoices dan 503 Service Unavailable de forma intermitente,
# no por un umbral fijo de limit (el mismo limit=10 fallo 4 veces seguidas en
# una corrida y funciono sin problema en la siguiente, incluso con respuestas
# de 800+ KB) - es inestabilidad real del servidor de Alegra bajo estos
# endpoints pesados, no algo que podamos calcular de antemano. Se reintenta
# con mas paciencia (6 intentos, hasta ~70s de espera acumulada) antes de
# fallar de verdad.
RETRY_STATUS_CODES = (503, 502, 504)
RETRY_MAX_INTENTOS = 6
RETRY_ESPERA_SEGUNDOS = (3, 5, 10, 20, 30)


class AlegraError(Exception):
    pass


def _headers_basic(email: str, token: str) -> dict:
    basic = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {
        "Authorization": f"Basic {basic}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def get(base_url: str, email: str, token: str, path: str, params: dict | None = None, timeout: int = 60):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    headers = _headers_basic(email, token)

    for intento in range(RETRY_MAX_INTENTOS):
        r = requests.get(url, headers=headers, params=params or {}, timeout=timeout)

        if r.status_code == 200:
            return r.json()

        if r.status_code in RETRY_STATUS_CODES and intento < RETRY_MAX_INTENTOS - 1:
            time.sleep(RETRY_ESPERA_SEGUNDOS[min(intento, len(RETRY_ESPERA_SEGUNDOS) - 1)])
            continue

        raise AlegraError(f"GET {path} {r.status_code}: {r.text}")


def paginate(base_url: str, email: str, token: str, path: str, extra_params: dict | None = None, limit: int = DEFAULT_LIMIT):
    """Generador que pagina con start/limit hasta que una pagina traiga menos
    de `limit` resultados. Maneja tanto respuestas de arreglo plano (la mayoria
    de catalogos/listados) como envueltas en {total, results[]} (confirmado
    solo para /taxes en Fase 0, pero el helper es generico por si aplica a mas)."""
    start = 0
    while True:
        params = {"start": start, "limit": limit}
        if extra_params:
            params.update(extra_params)

        payload = get(base_url, email, token, path, params=params)
        items = payload if isinstance(payload, list) else (payload.get("results") or [])

        if not items:
            break

        for item in items:
            yield item

        if len(items) < limit:
            break
        start += limit


def get_categories_tree(base_url: str, email: str, token: str):
    """/categories NO pagina - devuelve el arbol jerarquico completo en una
    sola llamada (confirmado en Fase 0, Plan Maestro seccion 6)."""
    return get(base_url, email, token, "categories", params={"limit": DEFAULT_LIMIT, "order_direction": "ASC"})


def flatten_categories(nodes: list, parent_id: str | None = None) -> list[dict]:
    """Aplana el arbol de /categories a filas para alegra_cuentas_contables,
    derivando parent_id de la posicion en el arbol (children[]), no de un
    campo 'parent' propio del payload."""
    flat = []
    for node in nodes or []:
        node_id = str(node.get("id"))
        rule = node.get("categoryRule") or {}

        flat.append({
            "id": node_id,
            "code": node.get("code") or None,
            "name": node.get("name"),
            "type": node.get("type"),
            "nature": node.get("nature"),
            "use": node.get("use"),
            "category_rule_key": rule.get("key"),
            "parent_id": parent_id,
        })

        flat.extend(flatten_categories(node.get("children") or [], parent_id=node_id))

    return flat


def flatten_journal_entries(journal: dict) -> list[dict]:
    """Aplana los renglones de un comprobante /journals a filas planas para
    alegra_movimientos. CONFIRMADO con dato real (2026-07-08, Importadora NGC,
    comprobantes 643/644/646): cada entrada de entries[] NO trae un sub-objeto
    'account' propio - el campo 'id' de la entrada ES el id de la cuenta
    contable (mismo id que /categories, ej. id 5008 = "Clientes Nacionales").
    El identificador unico real de la linea es 'idGlobal' (nunca visto null en
    la muestra); 'line' SI vino null en varias filas, no sirve como llave."""
    journal_id = str(journal.get("id"))
    fecha = journal.get("date")

    filas = []
    for entry in journal.get("entries") or []:
        cliente_linea = entry.get("client") or {}
        doc = entry.get("associatedDocument") or {}
        tercero_id = cliente_linea.get("id")

        filas.append({
            "journal_id": journal_id,
            "entry_id": str(entry.get("idGlobal")),
            "fecha": fecha,
            "alegra_account_id": str(entry.get("id")),
            "tercero_id": str(tercero_id) if tercero_id is not None else None,
            "debito": entry.get("debit") or 0,
            "credito": entry.get("credit") or 0,
            "descripcion": entry.get("description"),
            "associated_document_type": doc.get("resourceType"),
            "associated_document_id": str(doc.get("idResource")) if doc.get("idResource") is not None else None,
        })

    return filas
