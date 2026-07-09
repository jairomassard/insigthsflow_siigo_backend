"""
Paso de transformacion: alegra_movimientos -> auxiliar_contable (la MISMA
tabla que ya usa Siigo, poblada hoy por carga manual de Excel). Decision de
alcance (Plan Maestro, seccion 4.4-B, 2026-07-08): solo clientes Alegra con
codificacion tipo PUC (cuenta_codigo real, no sintetico) - los ~15 bloques de
reportes contables existentes (P&L, balance, IVA, retenciones, indicadores)
ya filtran por 'cuenta_codigo LIKE ...' contra esta tabla, sin modificarlos.

Filas de alegra_movimientos cuya cuenta no tiene codigo (categoryRule sin
PUC, tipico de clientes NIIF sin codificar) se OMITEN - auxiliar_contable.
cuenta_codigo es NOT NULL, y esos clientes quedan fuera de alcance por ahora
(ver pendiente en la seccion 4.4-B del plan).

Reemplazo total por cliente en cada corrida (DELETE + INSERT), no upsert
incremental - mismo patron que el flujo Excel-only de Siigo para esta tabla.
"""

import os
import sys

# Debe cargarse ANTES que cualquier import que toque crypto_utils/config (ver
# nota igual en alegra_sync_catalogos.py).
from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import text

from models import db


_DELETE_SQL = text("DELETE FROM auxiliar_contable WHERE idcliente = :idcliente")

_COUNT_TOTAL_SQL = text(
    "SELECT COUNT(*) FROM alegra_movimientos WHERE idcliente = :idcliente"
)

_COUNT_SIN_CODIGO_SQL = text("""
    SELECT COUNT(*)
    FROM alegra_movimientos m
    LEFT JOIN alegra_cuentas_contables c
        ON c.idcliente = m.idcliente AND c.alegra_id = m.alegra_account_id
    WHERE m.idcliente = :idcliente
      AND (c.code IS NULL OR c.code = '')
""")

_INSERT_SQL = text("""
    INSERT INTO auxiliar_contable (
        idcliente, fecha_contable, comprobante_tipo, comprobante_numero,
        cuenta_codigo, cuenta_nombre, tercero_nit, tercero_nombre,
        detalle, debito, credito, periodo_anio, periodo_mes
    )
    SELECT
        m.idcliente,
        m.fecha,
        'ALEGRA' AS comprobante_tipo,
        m.journal_id AS comprobante_numero,
        c.code AS cuenta_codigo,
        c.name AS cuenta_nombre,
        t.identificacion AS tercero_nit,
        t.nombre AS tercero_nombre,
        m.descripcion AS detalle,
        COALESCE(m.debito, 0) AS debito,
        COALESCE(m.credito, 0) AS credito,
        EXTRACT(YEAR FROM m.fecha)::int AS periodo_anio,
        EXTRACT(MONTH FROM m.fecha)::int AS periodo_mes
    FROM alegra_movimientos m
    JOIN alegra_cuentas_contables c
        ON c.idcliente = m.idcliente AND c.alegra_id = m.alegra_account_id
    LEFT JOIN alegra_terceros t
        ON t.idcliente = m.idcliente AND t.alegra_id = m.tercero_id
    WHERE m.idcliente = :idcliente
      AND c.code IS NOT NULL AND c.code <> ''
""")


def transform_auxiliar_contable_desde_alegra(idcliente: int) -> str:
    total = db.session.execute(_COUNT_TOTAL_SQL, {"idcliente": idcliente}).scalar()
    sin_codigo = db.session.execute(_COUNT_SIN_CODIGO_SQL, {"idcliente": idcliente}).scalar()

    db.session.execute(_DELETE_SQL, {"idcliente": idcliente})
    result = db.session.execute(_INSERT_SQL, {"idcliente": idcliente})
    db.session.commit()

    return (
        f"Transformacion auxiliar_contable Alegra (idcliente={idcliente}): "
        f"movimientos_totales={total}, insertados={result.rowcount}, "
        f"omitidos_sin_codigo={sin_codigo}."
    )


if __name__ == "__main__":
    try:
        from app import app
    except Exception:
        print("No se pudo importar 'app' desde app.py.")
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
        print(transform_auxiliar_contable_desde_alegra(cid))
