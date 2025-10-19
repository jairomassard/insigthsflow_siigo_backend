# backend/siigo/siigo_sync_productos.py
import os
import sys
import uuid
import requests
from datetime import datetime
from typing import Optional

from models import db, SiigoCredencial, SiigoProducto
from utils import _siigo_auth_json_for_client, _siigo_headers_bearer


def _parse_dt(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    try:
        return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
    except Exception:
        return None


def sync_productos_desde_siigo(idcliente: int) -> str:
    """
    Descarga productos de Siigo API y hace UPSERT en siigo_productos (multitenant).
    NO hardcodea idcliente y NO depende de create_app; se invoca dentro de un app_context.
    """
    cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
    if not cred:
        raise RuntimeError(f"Credenciales de Siigo no configuradas para idcliente={idcliente}")

    # Auth
    token_data = _siigo_auth_json_for_client(cred)
    token = token_data.get("access_token")
    if not token:
        raise RuntimeError(token_data.get("_error") or "No se pudo obtener token de Siigo")

    headers = _siigo_headers_bearer(token)
    base_url = (cred.base_url or "").rstrip("/")

    page = 1
    page_size = 100
    total_registros = 0
    nuevos, actualizados = 0, 0

    while True:
        url = f"{base_url}/v1/products?page={page}&page_size={page_size}"
        r = requests.get(url, headers=headers, timeout=60)
        if r.status_code != 200:
            raise RuntimeError(f"Error {r.status_code} consultando productos: {r.text}")

        payload = r.json() or {}
        productos = payload.get("results") or []
        if not productos:
            break

        for p in productos:
            total_registros += 1

            pid_raw = p.get("id")
            if not pid_raw:
                continue

            # Si el modelo usa UUID(as_uuid=True), conviene castear a uuid.UUID
            try:
                pid = uuid.UUID(str(pid_raw))
            except Exception:
                # Si tu modelo define 'id' como TEXT, cambia esto a: pid = str(pid_raw)
                pid = str(pid_raw)

            prod = SiigoProducto.query.filter_by(id=pid, idcliente=idcliente).first()
            is_new = False
            if not prod:
                prod = SiigoProducto(id=pid, idcliente=idcliente)
                db.session.add(prod)
                is_new = True

            # Mapear campos principales
            prod.code = p.get("code")
            prod.name = p.get("name")
            prod.type = p.get("type")

            acc = p.get("account_group") or {}
            prod.account_group_id = acc.get("id")
            prod.account_group_name = acc.get("name")

            unit = p.get("unit") or {}
            prod.unit_code = unit.get("code")
            prod.unit_name = unit.get("name")
            prod.unit_label = p.get("unit_label")

            prod.tax_classification = p.get("tax_classification")
            prod.tax_included = p.get("tax_included")
            prod.active = p.get("active")
            prod.stock_control = p.get("stock_control")
            prod.available_quantity = p.get("available_quantity")

            # JSONB
            prod.taxes = p.get("taxes")
            prod.warehouses = p.get("warehouses")
            prod.additional_fields = p.get("additional_fields")

            # Metadata
            meta = p.get("metadata") or {}
            cd = _parse_dt(meta.get("created"))
            ud = _parse_dt(meta.get("last_updated"))
            if cd:
                prod.metadata_created = cd
            if ud:
                prod.metadata_updated = ud

            if is_new:
                nuevos += 1
            else:
                actualizados += 1

        db.session.commit()

        if len(productos) < page_size:
            break
        page += 1

    return (
        f"Productos sincronizados (idcliente={idcliente}): "
        f"total={total_registros}, nuevos={nuevos}, actualizados={actualizados}."
    )


# --- Ejecución opcional por consola ---
# Uso:
#   python backend/siigo/siigo_sync_productos.py 1   (1 es el numero del cliente)
#   IDCLIENTE=1 python backend/siigo/siigo_sync_productos.py
if __name__ == "__main__":
    # Necesita un app_context. Si tu proyecto expone 'app' en app.py:
    try:
        from app import app  # importa tu instancia global de Flask
    except Exception as e:
        print("No se pudo importar 'app' desde app.py. Ejecuta esta función vía endpoint o ajusta este bloque.")
        sys.exit(1)

    cid = None
    if len(sys.argv) >= 2 and sys.argv[1].isdigit():
        cid = int(sys.argv[1])
    else:
        env_id = os.getenv("IDCLIENTE")
        if env_id and env_id.isdigit():
            cid = int(env_id)

    if not cid:
        print("Falta idcliente. Usa argumento numérico o variable de entorno IDCLIENTE.")
        sys.exit(1)

    with app.app_context():
        print(sync_productos_desde_siigo(cid))
