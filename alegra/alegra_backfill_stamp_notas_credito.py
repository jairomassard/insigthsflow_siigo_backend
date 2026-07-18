"""
Backfill puntual: rellena alegra_notas_credito.stamp para notas ya
sincronizadas antes de que el sync capturara ese campo (ver
Docs_integracion/alegra_agregar_stamp_notas_credito.sql).

El sync normal (alegra_sync_notas_credito.py) es incremental - para en la
primera nota ya conocida, no sirve para rellenar historico. Este script hace
una pasada completa de paginacion sobre /credit-notes (sin filtro de fecha) y
actualiza solo el campo stamp de cada nota ya existente, mismo patron usado
para el backfill de alegra_compra_items.tax.
"""

import sys

from dotenv import load_dotenv
load_dotenv()

from models import db
from models_alegra import AlegraNotaCredito
from alegra.alegra_api import ALEGRA_BASE_URL_DEFAULT, paginate
from alegra.alegra_sync_catalogos import _credenciales_alegra


def backfill_stamp_notas_credito(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)

    existentes = {
        n.alegra_id: n
        for n in AlegraNotaCredito.query.filter_by(idcliente=idcliente).all()
    }

    total, tocadas, sin_match = 0, 0, 0

    for cn in paginate(
        ALEGRA_BASE_URL_DEFAULT, email, token, "credit-notes",
        extra_params={"order_field": "date", "order_direction": "DESC"},
        limit=10,
    ):
        total += 1
        alegra_id = str(cn.get("id"))
        nota = existentes.get(alegra_id)
        if nota is None:
            sin_match += 1
            continue

        nota.stamp = cn.get("stamp")
        tocadas += 1
        if tocadas % 100 == 0:
            db.session.commit()
            print(f"  ...{tocadas} notas credito actualizadas", flush=True)

    db.session.commit()

    return (
        f"Backfill stamp notas credito Alegra (idcliente={idcliente}): "
        f"vistas={total}, actualizadas={tocadas}, sin_match_local={sin_match}."
    )


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")

    try:
        from app import app
    except Exception:
        print("No se pudo importar 'app' desde app.py.")
        sys.exit(1)

    if len(sys.argv) < 2 or not sys.argv[1].isdigit():
        print("Uso: python -m alegra.alegra_backfill_stamp_notas_credito <idcliente>")
        sys.exit(1)

    cid = int(sys.argv[1])

    with app.app_context():
        print(backfill_stamp_notas_credito(cid))
