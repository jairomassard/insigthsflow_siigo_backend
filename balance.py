from datetime import datetime, timedelta
from decimal import Decimal
from sqlalchemy import text

from models import db, AuxiliarSaldosCorte


# =========================================================
# Helpers básicos
# =========================================================

def safe_float(v):
    try:
        return float(v or 0)
    except Exception:
        return 0.0


def redondear(v, dec=2):
    return round(safe_float(v), dec)


def ultimo_dia_del_mes(fecha_str):
    dt = datetime.strptime(fecha_str, "%Y-%m-%d").date()
    if dt.month == 12:
        siguiente = dt.replace(year=dt.year + 1, month=1, day=1)
    else:
        siguiente = dt.replace(month=dt.month + 1, day=1)
    ultimo = siguiente - timedelta(days=1)
    return ultimo.strftime("%Y-%m-%d")


def ultimo_dia_mes_anterior(fecha_str):
    dt = datetime.strptime(fecha_str, "%Y-%m-%d").date()
    first_day = dt.replace(day=1)
    prev_last = first_day - timedelta(days=1)
    return prev_last.strftime("%Y-%m-%d")


def normalizar_fecha_comparacion(fecha_str):
    return ultimo_dia_del_mes(fecha_str)


# =========================================================
# Clasificación contable
# =========================================================

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
        if grupo in ("21", "22", "23", "24", "25", "26", "27", "28"):
            grupo_balance = "PASIVO_CORRIENTE"
        else:
            grupo_balance = "PASIVO_NO_CORRIENTE"

    elif clase == "3":
        seccion = "PATRIMONIO"
        grupo_balance = "PATRIMONIO"

    elif clase == "4":
        seccion = "INGRESOS"
        grupo_balance = "RESULTADO"

    elif clase == "5":
        seccion = "GASTOS"
        grupo_balance = "RESULTADO"

    elif clase in ("6", "7"):
        seccion = "COSTOS"
        grupo_balance = "RESULTADO"

    return {
        "clase": clase,
        "grupo": grupo,
        "cuenta_padre": cuenta_padre,
        "naturaleza": naturaleza,
        "seccion": seccion,
        "grupo_balance": grupo_balance,
    }


# =========================================================
# Snapshot acumulado
# =========================================================

def regenerar_snapshot_saldos_corte(idcliente: int, fecha_corte: str):
    fecha_corte = ultimo_dia_del_mes(fecha_corte)

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
          AND LEFT(cuenta_codigo, 1) IN ('1', '2', '3', '4', '5', '6', '7')
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

    AuxiliarSaldosCorte.query.filter_by(
        idcliente=idcliente,
        fecha_corte=fecha_corte
    ).delete()

    inserts = []
    for r in rows:
        cuenta_codigo = str(r["cuenta_codigo"]).strip()
        cuenta_nombre = str(r["cuenta_nombre"] or "").strip()
        saldo = safe_float(r["saldo"])

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
                saldo=Decimal(str(redondear(saldo, 2))),
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


def regenerar_snapshots_balance(idcliente: int, fecha_corte: str, comparar_con: str = None):
    fecha_corte = ultimo_dia_del_mes(fecha_corte)
    comparar_norm = normalizar_fecha_comparacion(comparar_con) if comparar_con else None

    principal = regenerar_snapshot_saldos_corte(idcliente, fecha_corte)

    comparativo = None
    if comparar_norm and comparar_norm != fecha_corte:
        comparativo = regenerar_snapshot_saldos_corte(idcliente, comparar_norm)

    return {
        "ok": True,
        "idcliente": idcliente,
        "fecha_corte": fecha_corte,
        "comparar_con": comparar_norm,
        "snapshot_principal": principal,
        "snapshot_comparativo": comparativo
    }


# =========================================================
# Helpers armado balance
# =========================================================

def _crear_item_snapshot(row, row_ant=None, modo_comparativo=True):
    saldo_actual = safe_float(row.saldo)
    saldo_anterior = safe_float(row_ant.saldo if row_ant else 0)

    variacion_abs = redondear(saldo_actual - saldo_anterior, 2) if modo_comparativo else 0
    variacion_pct = (
        redondear((variacion_abs / saldo_anterior) * 100, 2)
        if modo_comparativo and saldo_anterior != 0
        else 0
    )

    return {
        "cuenta": row.cuenta_codigo,
        "cuenta_padre": row.cuenta_padre,
        "nombre": row.cuenta_nombre,
        "seccion": row.seccion,
        "grupo_balance": row.grupo_balance,
        "saldo_actual": redondear(saldo_actual, 2),
        "saldo_anterior": redondear(saldo_anterior, 2) if modo_comparativo else None,
        "variacion_abs": variacion_abs if modo_comparativo else None,
        "variacion_pct": variacion_pct if modo_comparativo else None
    }


def _crear_item_sintetico(cuenta, nombre, seccion, grupo_balance, saldo_actual, saldo_anterior=0, modo_comparativo=True):
    variacion_abs = redondear(saldo_actual - saldo_anterior, 2) if modo_comparativo else 0
    variacion_pct = (
        redondear((variacion_abs / saldo_anterior) * 100, 2)
        if modo_comparativo and saldo_anterior != 0
        else 0
    )

    return {
        "cuenta": cuenta,
        "cuenta_padre": cuenta[:4] if len(cuenta) >= 4 else cuenta,
        "nombre": nombre,
        "seccion": seccion,
        "grupo_balance": grupo_balance,
        "saldo_actual": redondear(saldo_actual, 2),
        "saldo_anterior": redondear(saldo_anterior, 2) if modo_comparativo else None,
        "variacion_abs": variacion_abs if modo_comparativo else None,
        "variacion_pct": variacion_pct if modo_comparativo else None
    }


def _total(lista, campo):
    return redondear(sum(safe_float(x.get(campo, 0)) for x in lista), 2)


def _ordenar_items(lista):
    return sorted(lista, key=lambda x: (str(x.get("cuenta_padre", "")), str(x.get("cuenta", ""))))


def _armar_alertas(
    activo_corriente,
    activo_no_corriente,
    pasivo_corriente,
    pasivo_no_corriente,
    patrimonio,
    cuadratura
):
    alertas = []

    for item in activo_corriente + activo_no_corriente:
        if safe_float(item["saldo_actual"]) < 0:
            alertas.append(
                f"La cuenta de activo {item['cuenta']} - {item['nombre']} tiene saldo negativo y conviene revisarla."
            )

    for item in pasivo_corriente + pasivo_no_corriente:
        if safe_float(item["saldo_actual"]) < 0:
            alertas.append(
                f"La cuenta de pasivo {item['cuenta']} - {item['nombre']} tiene saldo negativo y conviene revisarla."
            )

    if len(patrimonio) == 0 or abs(_total(patrimonio, "saldo_actual")) < 1:
        alertas.append(
            "No se encontró patrimonio contable explícito en clase 3; se agregó una línea de ajuste para cuadrar el balance."
        )

    if abs(cuadratura) >= 1:
        alertas.append(
            "El balance no cuadraba de forma natural con las cuentas clasificadas, por eso se generó un ajuste de patrimonio calculado."
        )

    return alertas


def _armar_narrativa(
    patrimonio_total,
    razon_corriente,
    nivel_endeudamiento_pct,
    autonomia_financiera_pct,
    cuadratura_original,
    ajuste_patrimonio_aplicado,
    modo_comparativo
):
    narrativa = []

    if abs(cuadratura_original) < 1:
        narrativa.append("El balance cuadra correctamente con la información clasificada.")
    else:
        narrativa.append("El balance requirió un ajuste de patrimonio calculado para cuadrar la ecuación contable.")

    if patrimonio_total > 0:
        narrativa.append("La empresa presenta una posición patrimonial positiva.")
    elif patrimonio_total < 0:
        narrativa.append("La empresa presenta patrimonio negativo, lo que indica una situación financiera delicada.")
    else:
        narrativa.append("La empresa no muestra patrimonio neto en el corte evaluado.")

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

    if autonomia_financiera_pct >= 40:
        narrativa.append("La autonomía financiera es sólida.")
    elif autonomia_financiera_pct >= 20:
        narrativa.append("La autonomía financiera es moderada.")
    else:
        narrativa.append("La autonomía financiera es baja frente al tamaño de los activos.")

    if abs(ajuste_patrimonio_aplicado) >= 1:
        narrativa.append("Conviene revisar si el auxiliar incluye todas las cuentas de patrimonio o si falta reclasificación contable de cierre.")

    if not modo_comparativo:
        narrativa.append("Este balance se está mostrando en modo simple, sin comparación contra otro corte.")

    return narrativa


# =========================================================
# Construcción del balance general
# =========================================================

def construir_balance_general(idcliente: int, fecha_corte: str, comparar_con: str = None):
    fecha_corte = ultimo_dia_del_mes(fecha_corte)

    modo_comparativo = bool(comparar_con)
    comparar_con_norm = normalizar_fecha_comparacion(comparar_con) if comparar_con else None

    actuales = AuxiliarSaldosCorte.query.filter_by(
        idcliente=idcliente,
        fecha_corte=fecha_corte
    ).all()

    if not actuales:
        return {
            "ok": False,
            "error": "No existe snapshot para la fecha_corte solicitada. Debes regenerarlo primero."
        }

    anteriores = []
    snapshot_comparativo_existe = False

    if comparar_con_norm:
        anteriores = AuxiliarSaldosCorte.query.filter_by(
            idcliente=idcliente,
            fecha_corte=comparar_con_norm
        ).all()
        snapshot_comparativo_existe = len(anteriores) > 0

    map_ant = {x.cuenta_codigo: x for x in anteriores}

    activo_corriente = []
    activo_no_corriente = []
    pasivo_corriente = []
    pasivo_no_corriente = []
    patrimonio = []

    utilidad_actual = 0.0
    utilidad_anterior = 0.0

    for row in actuales:
        ant = map_ant.get(row.cuenta_codigo) if modo_comparativo and snapshot_comparativo_existe else None
        item = _crear_item_snapshot(row, ant, modo_comparativo=modo_comparativo and snapshot_comparativo_existe)

        clase = str(row.clase or "")[:1]

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

        if clase == "4":
            utilidad_actual += safe_float(row.saldo)
            utilidad_anterior += safe_float(ant.saldo if ant else 0)
        elif clase in ("5", "6", "7"):
            utilidad_actual -= safe_float(row.saldo)
            utilidad_anterior -= safe_float(ant.saldo if ant else 0)

    activo_corriente = _ordenar_items(activo_corriente)
    activo_no_corriente = _ordenar_items(activo_no_corriente)
    pasivo_corriente = _ordenar_items(pasivo_corriente)
    pasivo_no_corriente = _ordenar_items(pasivo_no_corriente)
    patrimonio = _ordenar_items(patrimonio)

    activo_corriente_total = _total(activo_corriente, "saldo_actual")
    activo_no_corriente_total = _total(activo_no_corriente, "saldo_actual")
    pasivo_corriente_total = _total(pasivo_corriente, "saldo_actual")
    pasivo_no_corriente_total = _total(pasivo_no_corriente, "saldo_actual")
    patrimonio_total = _total(patrimonio, "saldo_actual")

    activos_totales = redondear(activo_corriente_total + activo_no_corriente_total, 2)
    pasivos_totales = redondear(pasivo_corriente_total + pasivo_no_corriente_total, 2)

    cuadratura_original = redondear(activos_totales - (pasivos_totales + patrimonio_total), 2)

    ajuste_patrimonio_aplicado_actual = 0.0
    ajuste_patrimonio_aplicado_anterior = 0.0

    if abs(utilidad_actual) >= 1 or abs(utilidad_anterior) >= 1:
        patrimonio.append(
            _crear_item_sintetico(
                cuenta="39RESULTADO",
                nombre="Resultado acumulado calculado desde cuentas 4,5,6,7",
                seccion="PATRIMONIO",
                grupo_balance="PATRIMONIO",
                saldo_actual=utilidad_actual,
                saldo_anterior=utilidad_anterior,
                modo_comparativo=modo_comparativo and snapshot_comparativo_existe
            )
        )
        ajuste_patrimonio_aplicado_actual += utilidad_actual
        ajuste_patrimonio_aplicado_anterior += utilidad_anterior

    patrimonio = _ordenar_items(patrimonio)
    patrimonio_total = _total(patrimonio, "saldo_actual")

    cuadratura_post_resultado = redondear(activos_totales - (pasivos_totales + patrimonio_total), 2)

    if abs(cuadratura_post_resultado) >= 1:
        patrimonio.append(
            _crear_item_sintetico(
                cuenta="39AJUSTE",
                nombre="Ajuste de patrimonio calculado para cuadratura",
                seccion="PATRIMONIO",
                grupo_balance="PATRIMONIO",
                saldo_actual=cuadratura_post_resultado,
                saldo_anterior=0,
                modo_comparativo=modo_comparativo and snapshot_comparativo_existe
            )
        )
        ajuste_patrimonio_aplicado_actual += cuadratura_post_resultado

    patrimonio = _ordenar_items(patrimonio)

    patrimonio_total = _total(patrimonio, "saldo_actual")
    pasivo_mas_patrimonio = redondear(pasivos_totales + patrimonio_total, 2)
    capital_trabajo = redondear(activo_corriente_total - pasivo_corriente_total, 2)

    razon_corriente = redondear(
        activo_corriente_total / pasivo_corriente_total, 2
    ) if abs(pasivo_corriente_total) > 0 else 0

    nivel_endeudamiento_pct = redondear(
        (pasivos_totales / activos_totales) * 100, 2
    ) if abs(activos_totales) > 0 else 0

    autonomia_financiera_pct = redondear(
        (patrimonio_total / activos_totales) * 100, 2
    ) if abs(activos_totales) > 0 else 0

    cuadratura = redondear(activos_totales - pasivo_mas_patrimonio, 2)

    alertas = _armar_alertas(
        activo_corriente,
        activo_no_corriente,
        pasivo_corriente,
        pasivo_no_corriente,
        patrimonio,
        cuadratura_original
    )

    if modo_comparativo and comparar_con_norm and not snapshot_comparativo_existe:
        alertas.append(
            f"No existe snapshot del corte comparativo {comparar_con_norm}. Se está mostrando solo el balance del corte principal."
        )

    narrativa = _armar_narrativa(
        patrimonio_total=patrimonio_total,
        razon_corriente=razon_corriente,
        nivel_endeudamiento_pct=nivel_endeudamiento_pct,
        autonomia_financiera_pct=autonomia_financiera_pct,
        cuadratura_original=cuadratura_original,
        ajuste_patrimonio_aplicado=ajuste_patrimonio_aplicado_actual,
        modo_comparativo=modo_comparativo and snapshot_comparativo_existe
    )

    return {
        "ok": True,
        "fechas": {
            "fecha_corte": fecha_corte,
            "comparar_con": comparar_con_norm
        },
        "meta": {
            "modo_comparativo": bool(modo_comparativo and snapshot_comparativo_existe),
            "comparacion_solicitada": bool(comparar_con),
            "snapshot_comparativo_existe": snapshot_comparativo_existe,
            "explicacion_filtros": {
                "fecha_corte": "Muestra la situación financiera acumulada hasta esa fecha.",
                "comparar_con": "Permite comparar contra otro corte para analizar variaciones. Se recomienda usar cierres de mes."
            }
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
            "cuadratura": cuadratura,
            "cuadratura_original": cuadratura_original,
            "utilidad_calculada_actual": redondear(utilidad_actual, 2),
            "utilidad_calculada_anterior": redondear(utilidad_anterior, 2) if modo_comparativo and snapshot_comparativo_existe else None,
            "ajuste_patrimonio_aplicado_actual": redondear(ajuste_patrimonio_aplicado_actual, 2),
            "ajuste_patrimonio_aplicado_anterior": redondear(ajuste_patrimonio_aplicado_anterior, 2) if modo_comparativo and snapshot_comparativo_existe else None
        },
        "resumen": {
            "narrativa": narrativa,
            "alertas": alertas
        },
        "balance": {
            "activo_corriente": activo_corriente,
            "activo_no_corriente": activo_no_corriente,
            "pasivo_corriente": pasivo_corriente,
            "pasivo_no_corriente": pasivo_no_corriente,
            "patrimonio": patrimonio
        }
    }