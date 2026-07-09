"""
Sync de /journals -> alegra_movimientos. Requiere que los catalogos
(alegra_sync_catalogos.py) ya hayan corrido al menos una vez, porque
alegra_account_id/tercero_id son referencias blandas a alegra_cuentas_contables
y alegra_terceros (sin FK forzada en BD, mismo patron que Siigo - ver Plan
Maestro seccion 4.5, punto 2).

/journals no tiene filtro server-side de rango de fechas (confirmado en Fase
0), pero SI se puede pedir ordenado DESC por fecha. INCREMENTAL (2026-07-09):
se para de paginar apenas se llega a un comprobante con fecha anterior a la
ultima ya sincronizada, en vez de recorrer el historial completo en cada
corrida. Esto es seguro porque un comprobante contable, una vez posteado, no
cambia (confirmado en Fase 3: 564/564 comprobantes cuadrados debito=credito)
- a diferencia de facturas/compras/notas/pagos, aqui no hace falta re-revisar
comprobantes viejos.
"""

import os
import sys
from datetime import datetime

# Debe cargarse ANTES que cualquier import que toque crypto_utils/config (ver
# nota igual en alegra_sync_catalogos.py).
from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import func

from models import db
from models_alegra import AlegraMovimiento
from alegra.alegra_api import ALEGRA_BASE_URL_DEFAULT, paginate, flatten_journal_entries
from alegra.alegra_sync_catalogos import _credenciales_alegra


def sync_movimientos_desde_alegra(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)
    total_journals, total_filas, nuevos, actualizados = 0, 0, 0, 0

    # PERFORMANCE (2026-07-09): trae todas las lineas existentes en un solo
    # SELECT, en vez de un .filter_by().first() por cada una de las ~7000
    # lineas (esto ultimo tardaba varios minutos contra Railway por la
    # latencia de ida y vuelta de cada consulta individual).
    existentes = {
        (m.journal_id, m.entry_id): m
        for m in AlegraMovimiento.query.filter_by(idcliente=idcliente).all()
    }

    # None en la primera corrida (sin datos previos) -> sync completo, igual
    # que antes. Con datos previos -> solo se pagina hasta llegar a esta fecha.
    ultima_fecha = db.session.query(func.max(AlegraMovimiento.fecha)).filter(
        AlegraMovimiento.idcliente == idcliente
    ).scalar()

    # CONFIRMADO 2026-07-08 (Importadora NGC, cuenta de alto volumen): /journals
    # da 503 con limit=30 (el default general de la API) porque cada
    # comprobante embebe objetos de cliente completos por linea - la respuesta
    # se vuelve demasiado pesada. Probado 5/10/15/20 OK, 30 falla. Se usa 10
    # aqui con margen, no el DEFAULT_LIMIT general de alegra_api.py.
    for journal in paginate(
        ALEGRA_BASE_URL_DEFAULT, email, token, "journals",
        extra_params={"order_field": "date", "order_direction": "DESC"},
        limit=10,
    ):
        if ultima_fecha and journal.get("date"):
            fecha_journal = datetime.strptime(journal["date"], "%Y-%m-%d").date()
            if fecha_journal < ultima_fecha:
                break  # el resto del historial (ordenado DESC) ya esta sincronizado

        total_journals += 1

        for fila in flatten_journal_entries(journal):
            total_filas += 1
            clave = (fila["journal_id"], fila["entry_id"])

            mov = existentes.get(clave)
            is_new = mov is None
            if is_new:
                mov = AlegraMovimiento(
                    idcliente=idcliente,
                    journal_id=fila["journal_id"],
                    entry_id=fila["entry_id"],
                )
                db.session.add(mov)
                existentes[clave] = mov

            mov.fecha = datetime.strptime(fila["fecha"], "%Y-%m-%d").date() if fila["fecha"] else None
            mov.alegra_account_id = fila["alegra_account_id"]
            mov.tercero_id = fila["tercero_id"]
            mov.debito = fila["debito"]
            mov.credito = fila["credito"]
            mov.descripcion = fila["descripcion"]
            mov.associated_document_type = fila["associated_document_type"]
            mov.associated_document_id = fila["associated_document_id"]

            if is_new:
                nuevos += 1
            else:
                actualizados += 1

    db.session.commit()

    return (
        f"Movimientos Alegra (idcliente={idcliente}): "
        f"comprobantes={total_journals}, lineas={total_filas}, nuevos={nuevos}, actualizados={actualizados}."
    )


# --- Ejecucion opcional por consola ---
# Uso (correr desde backend/, con -m para que el paquete 'alegra' resuelva bien):
#   python -m alegra.alegra_sync_movimientos 1   (1 es el numero del cliente)
#   IDCLIENTE=1 python -m alegra.alegra_sync_movimientos
# En PowerShell, si aparece UnicodeEncodeError al importar app.py (emojis en
# los print de app.py vs consola cp1252), forzar UTF-8 antes:
#   $env:PYTHONIOENCODING = "utf-8"
if __name__ == "__main__":
    try:
        from app import app
    except Exception:
        print("No se pudo importar 'app' desde app.py. Ejecuta esta funcion via endpoint o ajusta este bloque.")
        sys.exit(1)

    cid = None
    if len(sys.argv) >= 2 and sys.argv[1].isdigit():
        cid = int(sys.argv[1])
    else:
        env_id = os.getenv("IDCLIENTE")
        if env_id and env_id.isdigit():
            cid = int(env_id)

    if not cid:
        print("Falta idcliente. Usa argumento numerico o variable de entorno IDCLIENTE.")
        sys.exit(1)

    with app.app_context():
        print(sync_movimientos_desde_alegra(cid))
