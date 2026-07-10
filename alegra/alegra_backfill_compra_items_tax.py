"""
Backfill puntual: rellena alegra_compra_items.tax para compras ya
sincronizadas antes de que el sync capturara ese campo (ver
Docs_integracion/alegra_agregar_tax_compra_items.sql).

El sync normal (alegra_sync_compras.py) es incremental - para en la primera
pagina ya conocida, no sirve para rellenar historico. Este script hace una
pasada completa de paginacion sobre /bills (sin filtro de fecha) y
reemplaza SOLO los items de cada compra ya existente, dejando el resto de
la compra (header, retenciones) intacto - mismo patron usado para el
backfill de factura_proveedor (2026-07-10).
"""

import sys

from dotenv import load_dotenv
load_dotenv()

from models import db
from models_alegra import AlegraCompra, AlegraCompraItem
from alegra.alegra_api import ALEGRA_BASE_URL_DEFAULT, paginate
from alegra.alegra_sync_catalogos import _credenciales_alegra


def backfill_tax_compra_items(idcliente: int) -> str:
    email, token = _credenciales_alegra(idcliente)

    existentes = {
        c.alegra_id: c
        for c in AlegraCompra.query.filter_by(idcliente=idcliente).all()
    }

    total, tocadas, sin_match = 0, 0, 0

    for bill in paginate(
        ALEGRA_BASE_URL_DEFAULT, email, token, "bills",
        extra_params={"order_field": "date", "order_direction": "DESC"},
        limit=10,
    ):
        total += 1
        alegra_id = str(bill.get("id"))
        compra = existentes.get(alegra_id)
        if compra is None:
            sin_match += 1
            continue

        purchases = bill.get("purchases") or {}
        AlegraCompraItem.query.filter_by(compra_id=compra.id).delete()

        for cat in purchases.get("categories") or []:
            db.session.add(AlegraCompraItem(
                compra_id=compra.id,
                idcliente=idcliente,
                tipo="categoria",
                cuenta_contable_id=str(cat.get("id")) if cat.get("id") is not None else None,
                descripcion=cat.get("name"),
                cantidad=None,
                precio=cat.get("price"),
                subtotal=None,
                total=cat.get("total"),
                tax=cat.get("tax"),
            ))

        for it in purchases.get("items") or []:
            db.session.add(AlegraCompraItem(
                compra_id=compra.id,
                idcliente=idcliente,
                tipo="item",
                producto_id=str(it.get("id")) if it.get("id") is not None else None,
                descripcion=it.get("name"),
                cantidad=it.get("quantity"),
                precio=it.get("price"),
                subtotal=it.get("subtotal"),
                total=it.get("total"),
                tax=it.get("tax"),
            ))

        tocadas += 1
        if tocadas % 100 == 0:
            db.session.commit()
            print(f"  ...{tocadas} compras actualizadas", flush=True)

    db.session.commit()

    return (
        f"Backfill tax compras Alegra (idcliente={idcliente}): "
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
        print("Uso: python -m alegra.alegra_backfill_compra_items_tax <idcliente>")
        sys.exit(1)

    cid = int(sys.argv[1])

    with app.app_context():
        print(backfill_tax_compra_items(cid))
