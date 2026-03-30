from datetime import datetime, timedelta
from decimal import Decimal
from sqlalchemy import text

from models import db, AuxiliarSaldosCorte

from datetime import datetime, timedelta
from decimal import Decimal
from sqlalchemy import text

from models import db, AuxiliarSaldosCorte


def safe_float(v):
    return float(v or 0)


def ultimo_dia_mes_anterior(fecha_str):
    dt = datetime.strptime(fecha_str, "%Y-%m-%d").date()
    first_day = dt.replace(day=1)
    prev_last = first_day - timedelta(days=1)
    return prev_last.strftime("%Y-%m-%d")


def clasificar_cuenta(cuenta_codigo: str):
    codigo = str(cuenta_codigo).strip()
    clase = codigo[:1]
    grupo = codigo[:2]
    cuenta_padre = codigo[:4] if len(codigo) >= 4 else codigo

    if clase in ("1", "5", "6", "7"):
        naturaleza = "DEBITO_MENOS_CREDITO"
    elif clase in ("2", "3", "4"):
        naturaleza = "CREDITO_MENOS_DEBITO"
    else:
        naturaleza = "NA"

    seccion = "OTROS"
    grupo_balance = "OTROS"

    if clase == "1":
        seccion = "ACTIVO"
        if grupo in ("11", "12", "13", "14"):
            grupo_balance = "ACTIVO_CORRIENTE"
        else:
            grupo_balance = "ACTIVO_NO_CORRIENTE"

    elif clase == "2":
        seccion = "PASIVO"
        if grupo in ("21", "22", "23", "24", "25", "27", "28"):
            grupo_balance = "PASIVO_CORRIENTE"
        else:
            grupo_balance = "PASIVO_NO_CORRIENTE"

    elif clase == "3":
        seccion = "PATRIMONIO"
        grupo_balance = "PATRIMONIO"

    elif clase == "4":
        seccion = "INGRESOS"
        grupo_balance = "RESULTADO"

    elif clase in ("6", "7"):
        seccion = "COSTOS"
        grupo_balance = "RESULTADO"

    elif clase == "5":
        seccion = "GASTOS"
        grupo_balance = "RESULTADO"

    return {
        "clase": clase,
        "grupo": grupo,
        "cuenta_padre": cuenta_padre,
        "naturaleza": naturaleza,
        "seccion": seccion,
        "grupo_balance": grupo_balance,
    }


def regenerar_snapshot_saldos_corte(idcliente: int, fecha_corte: str):
    """
    Recalcula e inserta los saldos acumulados por cuenta
    para un cliente y una fecha de corte.
    """

    sql = text("""
        SELECT
            cuenta_codigo,
            MAX(cuenta_nombre) AS cuenta_nombre,
            SUM(
                CASE
                    WHEN LEFT(cuenta_codigo, 1) IN ('1', '5', '6', '7')
                        THEN (debito - credito)
                    WHEN LEFT(cuenta_codigo, 1) IN ('2', '3', '4')
                        THEN (credito - debito)
                    ELSE 0
                END
            ) AS saldo
        FROM auxiliar_contable
        WHERE idcliente = :idc
          AND fecha_contable <= :fc
        GROUP BY cuenta_codigo
        HAVING SUM(
            CASE
                WHEN LEFT(cuenta_codigo, 1) IN ('1', '5', '6', '7')
                    THEN (debito - credito)
                WHEN LEFT(cuenta_codigo, 1) IN ('2', '3', '4')
                    THEN (credito - debito)
                ELSE 0
            END
        ) <> 0
        ORDER BY cuenta_codigo
    """)

    rows = db.session.execute(sql, {
        "idc": idcliente,
        "fc": fecha_corte
    }).mappings().all()

    # Borrar snapshot previo del mismo cliente y fecha
    AuxiliarSaldosCorte.query.filter_by(
        idcliente=idcliente,
        fecha_corte=fecha_corte
    ).delete()

    inserts = []
    for r in rows:
        cuenta_codigo = str(r["cuenta_codigo"]).strip()
        cuenta_nombre = str(r["cuenta_nombre"] or "").strip()
        saldo = float(r["saldo"] or 0)

        meta = clasificar_cuenta(cuenta_codigo)

        inserts.append(
            AuxiliarSaldosCorte(
                idcliente=idcliente,
                fecha_corte=fecha_corte,
                cuenta_codigo=cuenta_codigo,
                cuenta_nombre=cuenta_nombre,
                cuenta_padre=meta["cuenta_padre"],
                clase=meta["clase"],
                grupo=meta["grupo"],
                seccion=meta["seccion"],
                grupo_balance=meta["grupo_balance"],
                naturaleza=meta["naturaleza"],
                saldo=Decimal(str(round(saldo, 2))),
                origen="AUXILIAR"
            )
        )

    db.session.bulk_save_objects(inserts)
    db.session.commit()

    return {
        "ok": True,
        "idcliente": idcliente,
        "fecha_corte": fecha_corte,
        "registros_generados": len(inserts)
    }


def construir_balance_general(idcliente: int, fecha_corte: str, comparar_con: str = None):
    if not comparar_con:
        comparar_con = ultimo_dia_mes_anterior(fecha_corte)

    actuales = AuxiliarSaldosCorte.query.filter_by(
        idcliente=idcliente,
        fecha_corte=fecha_corte
    ).all()

    anteriores = AuxiliarSaldosCorte.query.filter_by(
        idcliente=idcliente,
        fecha_corte=comparar_con
    ).all()

    if not actuales:
        return {
            "ok": False,
            "error": "No existe snapshot para la fecha_corte solicitada. Debes regenerarlo primero."
        }

    map_ant = {x.cuenta_codigo: x for x in anteriores}

    activo_corriente = []
    activo_no_corriente = []
    pasivo_corriente = []
    pasivo_no_corriente = []
    patrimonio = []

    for row in actuales:
        ant = map_ant.get(row.cuenta_codigo)

        item = {
            "cuenta": row.cuenta_codigo,
            "cuenta_padre": row.cuenta_padre,
            "nombre": row.cuenta_nombre,
            "seccion": row.seccion,
            "grupo_balance": row.grupo_balance,
            "saldo_actual": safe_float(row.saldo),
            "saldo_anterior": safe_float(ant.saldo if ant else 0),
        }

        item["variacion_abs"] = round(item["saldo_actual"] - item["saldo_anterior"], 2)
        item["variacion_pct"] = round(
            (item["variacion_abs"] / item["saldo_anterior"]) * 100, 2
        ) if item["saldo_anterior"] != 0 else 0

        if row.grupo_balance == "ACTIVO_CORRIENTE":
            activo_corriente.append(item)
        elif row.grupo_balance == "ACTIVO_NO_CORRIENTE":
            activo_no_corriente.append(item)
        elif row.grupo_balance == "PASIVO_CORRIENTE":
            pasivo_corriente.append(item)
        elif row.grupo_balance == "PASIVO_NO_CORRIENTE":
            pasivo_no_corriente.append(item)
        elif row.grupo_balance == "PATRIMONIO":
            patrimonio.append(item)

    def total(lista, campo):
        return round(sum(x[campo] for x in lista), 2)

    activo_corriente_total = total(activo_corriente, "saldo_actual")
    activo_no_corriente_total = total(activo_no_corriente, "saldo_actual")
    pasivo_corriente_total = total(pasivo_corriente, "saldo_actual")
    pasivo_no_corriente_total = total(pasivo_no_corriente, "saldo_actual")
    patrimonio_total = total(patrimonio, "saldo_actual")

    activos_totales = round(activo_corriente_total + activo_no_corriente_total, 2)
    pasivos_totales = round(pasivo_corriente_total + pasivo_no_corriente_total, 2)
    pasivo_mas_patrimonio = round(pasivos_totales + patrimonio_total, 2)
    capital_trabajo = round(activo_corriente_total - pasivo_corriente_total, 2)

    razon_corriente = round(
        activo_corriente_total / pasivo_corriente_total, 2
    ) if pasivo_corriente_total != 0 else 0

    nivel_endeudamiento_pct = round(
        (pasivos_totales / activos_totales) * 100, 2
    ) if activos_totales != 0 else 0

    autonomia_financiera_pct = round(
        (patrimonio_total / activos_totales) * 100, 2
    ) if activos_totales != 0 else 0

    cuadratura = round(activos_totales - pasivo_mas_patrimonio, 2)

    narrativa = []

    if cuadratura == 0:
        narrativa.append("El balance cuadra correctamente.")
    else:
        narrativa.append("El balance no cuadra. Conviene revisar patrimonio o clasificación contable.")

    if razon_corriente >= 1.5:
        narrativa.append("La liquidez de corto plazo luce saludable.")
    elif razon_corriente >= 1:
        narrativa.append("La liquidez es aceptable, pero debe monitorearse.")
    else:
        narrativa.append("La liquidez de corto plazo es débil.")

    if nivel_endeudamiento_pct <= 50:
        narrativa.append("El endeudamiento está en una zona manejable.")
    elif nivel_endeudamiento_pct <= 70:
        narrativa.append("El endeudamiento es relevante y debe vigilarse.")
    else:
        narrativa.append("El endeudamiento es alto frente al total de activos.")

    return {
        "ok": True,
        "fechas": {
            "fecha_corte": fecha_corte,
            "comparar_con": comparar_con
        },
        "kpis": {
            "activo_corriente": activo_corriente_total,
            "activo_no_corriente": activo_no_corriente_total,
            "activos_totales": activos_totales,
            "pasivo_corriente": pasivo_corriente_total,
            "pasivo_no_corriente": pasivo_no_corriente_total,
            "pasivos_totales": pasivos_totales,
            "patrimonio_total": patrimonio_total,
            "pasivo_mas_patrimonio": pasivo_mas_patrimonio,
            "capital_trabajo": capital_trabajo,
            "razon_corriente": razon_corriente,
            "nivel_endeudamiento_pct": nivel_endeudamiento_pct,
            "autonomia_financiera_pct": autonomia_financiera_pct,
            "cuadratura": cuadratura
        },
        "resumen": {
            "narrativa": narrativa
        },
        "balance": {
            "activo_corriente": activo_corriente,
            "activo_no_corriente": activo_no_corriente,
            "pasivo_corriente": pasivo_corriente,
            "pasivo_no_corriente": pasivo_no_corriente,
            "patrimonio": patrimonio
        }
    }