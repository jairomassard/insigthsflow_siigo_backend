from datetime import datetime, timedelta
from decimal import Decimal
from collections import defaultdict
from sqlalchemy import text, func

from models import db, AuxiliarSaldosCorte, BalancePrueba


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
# Reglas contables auxiliares
# =========================================================

def es_cuenta_contra_activo(cuenta_codigo: str, nombre: str = ""):
    codigo = str(cuenta_codigo or "").strip()
    nombre_l = str(nombre or "").strip().lower()

    if codigo.startswith(("1592", "1596", "1698", "1798")):
        return True

    if "depreci" in nombre_l or "amortiz" in nombre_l:
        return True

    if "devolución" in nombre_l or "devolucion" in nombre_l:
        return True

    return False


def es_cuenta_contra_pasivo(cuenta_codigo: str, nombre: str = ""):
    codigo = str(cuenta_codigo or "").strip()
    nombre_l = str(nombre or "").strip().lower()

    if "devolución" in nombre_l or "devolucion" in nombre_l:
        return True

    if codigo.startswith(("236", "240", "250", "251")):
        if "devol" in nombre_l or "descontable" in nombre_l:
            return True

    return False


def es_cuenta_impuesto_o_retencion(cuenta_codigo: str, nombre: str = ""):
    codigo = str(cuenta_codigo or "").strip()
    nombre_l = str(nombre or "").strip().lower()

    return (
        codigo.startswith(("1355", "2365", "2367", "2368", "2408"))
        or "rete" in nombre_l
        or "iva" in nombre_l
        or "impuesto" in nombre_l
        or "retención" in nombre_l
        or "retencion" in nombre_l
    )

def es_cuenta_iva_descontable_presentacion_pasivo(cuenta_codigo: str, nombre: str = ""):
    codigo = str(cuenta_codigo or "").strip()
    nombre_l = str(nombre or "").strip().lower()

    return (
        codigo.startswith(("240810", "240815"))
        or "descontable" in nombre_l
        or "saldo a favor en iva" in nombre_l
    )

def es_cuenta_transitoria_o_legalizacion(cuenta_codigo: str, nombre: str = ""):
    nombre_l = str(nombre or "").strip().lower()
    return (
        "legalizar" in nombre_l
        or "anticip" in nombre_l
        or nombre_l == "otros"
        or nombre_l.startswith("otros ")
    )


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
# Cobertura Alegra sin código PUC, para Balance General
# =========================================================

def _cobertura_balance_sin_codigo(idcliente: int, fecha_corte: str):
    """Cuentas Alegra sin código PUC de tipo asset/liability/equity
    (misma tabla alegra_cobertura_contable que ya usa calcular_cobertura_alegra
    para el PyG), acumuladas hasta fecha_corte y netas por tipo. Para Siigo,
    o Alegra sin este mecanismo activo, la tabla está vacía y esto devuelve
    todo en cero - sin efecto.

    A diferencia del PyG (donde el "cajón" no importa porque la Utilidad
    Neta no cambia), en el Balance sí importa clasificar bien Activo/
    Pasivo/Patrimonio - y hay un riesgo real de incluir basura: con datos
    reales de Maslux LED (idcliente=16, 2026-09) se encontró una corrección
    contable mal hecha en Alegra ("el sistema estaba parametrizando todos
    los items como inventarios") que dejó ~$25.7 mil millones sin código en
    una cuenta de Inventarios/Inversiones - ~46x el tamaño real del balance
    de ese cliente. Por eso el caller de esta función debe aplicar un
    chequeo de plausibilidad antes de sumar esto al snapshot (ver uso en
    regenerar_snapshot_saldos_corte) - esta función solo agrega y neta,
    no decide si es seguro incluirlo."""
    # LEFT JOIN por nombre contra el catálogo real de Alegra para traer
    # category_rule_key - alegra_cobertura_contable no lo guarda (se
    # capturó antes de que este campo hiciera falta para nada), pero el
    # nombre de cuenta es estable dentro del mismo cliente, así que el
    # join por nombre es confiable. Se usa en construir_flujo_efectivo
    # para clasificar mejor que "es activo/pasivo/patrimonio" a secas
    # (ej. distinguir Capital real de Utilidades acumuladas dentro de
    # "equity", o una Obligación Financiera de una cuenta por pagar
    # operativa dentro de "liability") - Balance General ignora este
    # campo, no le afecta en nada.
    filas = db.session.execute(text("""
        SELECT cc.cuenta_nombre, cc.tipo_cuenta,
               SUM(cc.debito) AS debito, SUM(cc.credito) AS credito,
               MAX(acc.category_rule_key) AS category_rule_key
        FROM alegra_cobertura_contable cc
        LEFT JOIN alegra_cuentas_contables acc
            ON acc.idcliente = cc.idcliente AND acc.name = cc.cuenta_nombre
        WHERE cc.idcliente = :idc AND cc.fecha <= :fc
          AND cc.tipo_cuenta IN ('asset', 'liability', 'equity')
        GROUP BY cc.cuenta_nombre, cc.tipo_cuenta
    """), {"idc": idcliente, "fc": fecha_corte}).mappings().all()

    neto_por_tipo = {"asset": 0.0, "liability": 0.0, "equity": 0.0}
    detalle = []
    for f in filas:
        debito = safe_float(f["debito"])
        credito = safe_float(f["credito"])
        neto = (debito - credito) if f["tipo_cuenta"] == "asset" else (credito - debito)
        neto_por_tipo[f["tipo_cuenta"]] += neto
        if abs(neto) >= 1:
            detalle.append({
                "cuenta_nombre": f["cuenta_nombre"],
                "tipo_cuenta": f["tipo_cuenta"],
                "category_rule_key": f["category_rule_key"],
                "neto": redondear(neto, 2)
            })

    return neto_por_tipo, detalle


# Umbral de plausibilidad: si lo sin-código de un tipo (activo/pasivo/
# patrimonio) supera esta cantidad de veces el tamaño ya clasificado del
# cliente, se considera sospechoso y NO se suma al snapshot (queda solo
# visible en el detalle de cobertura del reporte, para revisión humana).
UMBRAL_MULTIPLICADOR_COBERTURA_BALANCE = 2.0

# (código sintético, clase/grupo que hace que clasificar_cuenta() lo
# resuelva correctamente, nombre a mostrar)
_MAPA_SINTETICO_COBERTURA = {
    "asset": ("13999999", "Activo Alegra sin código PUC (clasificado por tipo)"),
    "liability": ("23999999", "Pasivo Alegra sin código PUC (clasificado por tipo)"),
    "equity": ("39999998", "Patrimonio Alegra sin código PUC (clasificado por tipo)"),
}


def _agregar_filas_sin_codigo_si_es_seguro(rows, idcliente, fecha_corte):
    """Agrega a `rows` (in-place, vía append) una fila sintética por cada
    tipo (asset/liability/equity) con movimiento sin código PUC, siempre
    que pase el chequeo de plausibilidad. Ver _cobertura_balance_sin_codigo
    para el contexto completo (caso real Maslux)."""
    neto_por_tipo, _detalle = _cobertura_balance_sin_codigo(idcliente, fecha_corte)

    if not any(abs(v) >= 1 for v in neto_por_tipo.values()):
        return

    activo_clasificado = sum(
        safe_float(r["saldo"]) for r in rows if str(r["cuenta_codigo"]).strip().startswith("1")
    )
    pasivo_clasificado = sum(
        safe_float(r["saldo"]) for r in rows if str(r["cuenta_codigo"]).strip().startswith("2")
    )
    patrimonio_clasificado = sum(
        safe_float(r["saldo"]) for r in rows if str(r["cuenta_codigo"]).strip().startswith("3")
    )
    clasificado_por_tipo = {
        "asset": activo_clasificado,
        "liability": pasivo_clasificado,
        "equity": patrimonio_clasificado,
    }
    # Escala de referencia del cliente (tamaño de su activo ya clasificado);
    # sirve de piso cuando el propio cajón (ej. patrimonio) está en $0.
    escala_cliente = max(abs(activo_clasificado), 1.0)

    for tipo, (codigo_sintetico, nombre) in _MAPA_SINTETICO_COBERTURA.items():
        neto = neto_por_tipo.get(tipo, 0.0)
        if abs(neto) < 1:
            continue
        referencia = max(abs(clasificado_por_tipo[tipo]), escala_cliente)
        if abs(neto) > UMBRAL_MULTIPLICADOR_COBERTURA_BALANCE * referencia:
            continue  # outlier, no se suma - ver docstring de _cobertura_balance_sin_codigo
        rows.append({
            "cuenta_codigo": codigo_sintetico,
            "cuenta_nombre": nombre,
            "saldo": neto,
        })


_CODIGOS_SINTETICOS_COBERTURA = {v[0] for v in _MAPA_SINTETICO_COBERTURA.values()}


def calcular_cobertura_balance_alegra(idcliente: int, fecha_corte: str):
    """Para el banner de transparencia del Balance General (mismo principio
    que calcular_cobertura_alegra del PyG, en app.py): cuánta plata Alegra
    sin código PUC hay, cuánta se incluyó en el balance (pasó el chequeo de
    plausibilidad) y cuánta se excluyó por sospechosa. Se recalcula en cada
    consulta del reporte (no se persiste) - mismo patrón que el PyG."""
    neto_por_tipo, detalle = _cobertura_balance_sin_codigo(idcliente, fecha_corte)

    vacio = {
        "monto_incluido": 0.0,
        "monto_excluido_por_revisar": 0.0,
        "detalle_incluido": [],
        "detalle_excluido": [],
    }
    if not any(abs(v) >= 1 for v in neto_por_tipo.values()):
        return vacio

    filas_snapshot = AuxiliarSaldosCorte.query.filter_by(
        idcliente=idcliente, fecha_corte=fecha_corte
    ).all()

    def _clasificado(prefijo):
        return sum(
            safe_float(r.saldo) for r in filas_snapshot
            if str(r.cuenta_codigo).strip().startswith(prefijo)
            and str(r.cuenta_codigo).strip() not in _CODIGOS_SINTETICOS_COBERTURA
        )

    clasificado_por_tipo = {
        "asset": _clasificado("1"),
        "liability": _clasificado("2"),
        "equity": _clasificado("3"),
    }
    escala_cliente = max(abs(clasificado_por_tipo["asset"]), 1.0)

    detalle_incluido = []
    detalle_excluido = []
    monto_incluido = 0.0
    monto_excluido = 0.0

    for tipo, (_codigo, _nombre) in _MAPA_SINTETICO_COBERTURA.items():
        neto = neto_por_tipo.get(tipo, 0.0)
        if abs(neto) < 1:
            continue
        referencia = max(abs(clasificado_por_tipo[tipo]), escala_cliente)
        item = {
            "tipo_cuenta": tipo,
            "monto": round(neto, 2),
            "cuentas": [d for d in detalle if d["tipo_cuenta"] == tipo],
        }
        if abs(neto) > UMBRAL_MULTIPLICADOR_COBERTURA_BALANCE * referencia:
            detalle_excluido.append(item)
            monto_excluido += abs(neto)
        else:
            detalle_incluido.append(item)
            monto_incluido += abs(neto)

    return {
        "monto_incluido": round(monto_incluido, 2),
        "monto_excluido_por_revisar": round(monto_excluido, 2),
        "detalle_incluido": detalle_incluido,
        "detalle_excluido": detalle_excluido,
    }


# =========================================================
# Cobertura Alegra sin código PUC, para Flujo de Efectivo
# =========================================================
#
# A diferencia de Balance General (que solo necesita un neto por tipo -
# activo/pasivo/patrimonio - para inyectar un código sintético en el
# snapshot), Flujo de Efectivo necesita saber a cuál de sus 4 categorías
# (operación/inversión/financiación/excluido) pertenece cada cuenta sin
# código, porque mezclarlas mal significa contar como "operación" una
# entrada de capital real, o algo peor, como se investigó con datos reales
# de Maslux LED (idcliente=16, 2026-09). Por eso se usa category_rule_key
# de Alegra (alegra_cuentas_contables) - su propia taxonomía semántica de
# cuentas, disponible incluso sin código PUC - más un respaldo por nombre
# en español para lo que Alegra no categoriza.
#
# Encuesta real (2026-09) de los únicos valores de category_rule_key que
# existen hoy en producción para tipo liability/equity, sobre los clientes
# Alegra reales (15=NGC, 16=Maslux) + demo (17):
#   equity:    EQUITY, INITIAL_ADJUSTMENTS_BANKS, INITIAL_ADJUSTMENTS_INVENTORY,
#              LOSS_OF_PERIOD, UTILITIES, UTILITIES_PERIOD, (vacío)
#   liability: ADVANCE_IN, DEBTS_TO_PAY_CREDIT_CARDS, DEBTS_TO_PAY_PROVIDERS,
#              DEBTS_TO_PAY_RETURNS, FUENTE_RETENTION_TO_PAY_COL, ICO_TO_PAY_COL,
#              INDUSTRY_RETENTION_TO_PAY_COL, IVA_REFUNDED_ON_SALES_COL,
#              IVA_RETENTION_TO_PAY_COL, IVA_TO_PAY_COL, LIABILITIES,
#              OTHER_RETENTION_TYPE_TO_PAY, OTHER_TAX_TYPE_TO_PAY,
#              RETENTIONS_TO_PAY, TAXES_TO_PAY, (vacío)
# Notablemente Alegra NO tiene una categoría propia para "Obligaciones
# Financieras" ni "Socios" como pasivo - de ahí que el respaldo por nombre
# sea imprescindible para pasivo, no solo un extra.

_LIABILITY_CRK_FINANCIACION = {"DEBTS_TO_PAY_CREDIT_CARDS"}
_LIABILITY_CRK_OPERACION = {
    "ADVANCE_IN", "DEBTS_TO_PAY_PROVIDERS", "DEBTS_TO_PAY_RETURNS",
    "FUENTE_RETENTION_TO_PAY_COL", "ICO_TO_PAY_COL", "INDUSTRY_RETENTION_TO_PAY_COL",
    "IVA_REFUNDED_ON_SALES_COL", "IVA_RETENTION_TO_PAY_COL", "IVA_TO_PAY_COL",
    "OTHER_RETENTION_TYPE_TO_PAY", "OTHER_TAX_TYPE_TO_PAY", "RETENTIONS_TO_PAY",
    "TAXES_TO_PAY",
}
_PALABRAS_FINANCIACION_PASIVO = (
    "obligación financ", "obligacion financ", "préstamo", "prestamo",
    "socio", "accionista", "leasing", "pagaré", "pagare",
    "crédito bancario", "credito bancario", "tarjeta de crédito", "tarjeta de credito",
)

_EQUITY_CRK_EXCLUIDO = {"UTILITIES", "UTILITIES_PERIOD", "LOSS_OF_PERIOD"}
_PALABRAS_EXCLUIDO_PATRIMONIO = (
    "utilidad", "resultado", "pérdida", "perdida", "excedente", "ganancias acumulad", "ganancia acumulad",
)
_PALABRAS_FINANCIACION_PATRIMONIO = ("capital", "aporte", "reserva")

_PALABRAS_ACTIVO_NO_CORRIENTE = (
    "propiedad, planta", "propiedad planta", "activo fijo", "activos fijos",
    "intangible", "inversion a largo plazo", "inversión a largo plazo",
)


def _clasificar_categoria_flujo_efectivo_alegra(tipo_cuenta: str, category_rule_key, cuenta_nombre: str):
    """Devuelve 'operacion' | 'inversion' | 'financiacion' | 'excluido' para
    una cuenta Alegra sin código PUC, usando category_rule_key + nombre.
    Ver docstring de la sección arriba para el contexto completo."""
    crk = str(category_rule_key or "").strip().upper()
    nombre_l = str(cuenta_nombre or "").strip().lower()

    if tipo_cuenta == "equity":
        if crk.startswith("INITIAL_ADJUSTMENTS") or crk in _EQUITY_CRK_EXCLUIDO:
            return "excluido"  # ajuste de carga de saldo inicial o resultado del ejercicio, no es flujo real
        if crk == "EQUITY":
            return "financiacion"
        if any(p in nombre_l for p in _PALABRAS_EXCLUIDO_PATRIMONIO):
            return "excluido"
        if any(p in nombre_l for p in _PALABRAS_FINANCIACION_PATRIMONIO):
            return "financiacion"
        return "excluido"  # patrimonio sin certeza: por defecto no se cuenta como entrada de caja real

    if tipo_cuenta == "liability":
        if crk in _LIABILITY_CRK_FINANCIACION:
            return "financiacion"
        if crk in _LIABILITY_CRK_OPERACION:
            return "operacion"
        if any(p in nombre_l for p in _PALABRAS_FINANCIACION_PASIVO):
            return "financiacion"
        return "operacion"  # igual que el comportamiento actual (pasivo corriente operativo)

    if tipo_cuenta == "asset":
        if crk == "BANK_ACCOUNTS" or "banco" in nombre_l or nombre_l.strip() == "caja":
            return "excluido"  # cuenta de caja/bancos sin código: ya queda fuera de caja_inicial/caja_final, no duplicar
        if es_cuenta_contra_activo("", cuenta_nombre):
            return "excluido"  # ya revertido vía dep_amort en operación
        if crk == "FIXED_ASSET" or any(p in nombre_l for p in _PALABRAS_ACTIVO_NO_CORRIENTE):
            return "inversion"
        return "operacion"  # activo corriente: capital de trabajo

    return "excluido"


def cobertura_flujo_efectivo_sin_codigo_alegra(
    idcliente: int, fecha_inicio: str, fecha_fin: str, deltas_clasificados: dict
):
    """Para Flujo de Efectivo (Alegra): calcula el DELTA del período (fin
    menos inicio) de cada cuenta sin código PUC, la clasifica en
    operación/inversión/financiación/excluido, y aplica un chequeo de
    plausibilidad por bucket (no por tipo activo/pasivo/patrimonio como
    hace Balance General) comparando contra `deltas_clasificados` - los
    totales YA calculados por el caller a partir de las cuentas CON código
    para ese mismo período, que sirven de escala de referencia de este
    cliente en este período.

    Devuelve (delta_por_bucket, detalle_por_bucket, excluidos_por_revisar).
    delta_por_bucket trae solo 'operacion'/'inversion'/'financiacion' (ya
    con el efecto en caja aplicado, mismo signo que usa el loop principal
    de construir_flujo_efectivo). detalle_por_bucket también incluye
    'excluido'. excluidos_por_revisar son montos que se descartaron por
    implausibles (mismo espíritu que calcular_cobertura_balance_alegra)."""
    _neto_ini, detalle_ini = _cobertura_balance_sin_codigo(idcliente, fecha_inicio)
    _neto_fin, detalle_fin = _cobertura_balance_sin_codigo(idcliente, fecha_fin)

    por_cuenta_ini = {(d["cuenta_nombre"], d["tipo_cuenta"]): d["neto"] for d in detalle_ini}
    por_cuenta_fin = {(d["cuenta_nombre"], d["tipo_cuenta"]): d["neto"] for d in detalle_fin}
    categoria_por_cuenta = {
        (d["cuenta_nombre"], d["tipo_cuenta"]): d["category_rule_key"] for d in detalle_ini
    }
    categoria_por_cuenta.update({
        (d["cuenta_nombre"], d["tipo_cuenta"]): d["category_rule_key"] for d in detalle_fin
    })

    escala_cliente = max(
        abs(deltas_clasificados.get("operacion", 0.0)),
        abs(deltas_clasificados.get("inversion", 0.0)),
        abs(deltas_clasificados.get("financiacion", 0.0)),
        1.0,
    )

    delta_por_bucket = {"operacion": 0.0, "inversion": 0.0, "financiacion": 0.0}
    detalle_por_bucket = {"operacion": [], "inversion": [], "financiacion": [], "excluido": []}
    excluidos_por_revisar = []

    for clave in (set(por_cuenta_ini) | set(por_cuenta_fin)):
        nombre, tipo = clave
        delta = por_cuenta_fin.get(clave, 0.0) - por_cuenta_ini.get(clave, 0.0)
        if abs(delta) < 1:
            continue

        crk = categoria_por_cuenta.get(clave)
        bucket = _clasificar_categoria_flujo_efectivo_alegra(tipo, crk, nombre)
        efecto_caja = -delta if tipo == "asset" else delta
        item = {
            "cuenta": nombre,
            "nombre": nombre,
            "tipo_cuenta": tipo,
            "category_rule_key": crk,
            "delta": redondear(delta, 2),
        }

        if bucket == "excluido":
            detalle_por_bucket["excluido"].append(item)
            continue

        referencia = max(abs(deltas_clasificados.get(bucket, 0.0)), escala_cliente)
        if abs(efecto_caja) > UMBRAL_MULTIPLICADOR_COBERTURA_BALANCE * referencia:
            item["motivo_exclusion"] = "monto_sin_codigo_implausible"
            excluidos_por_revisar.append(item)
            continue

        item["efecto_caja"] = redondear(efecto_caja, 2)
        delta_por_bucket[bucket] += efecto_caja
        detalle_por_bucket[bucket].append(item)

    return delta_por_bucket, detalle_por_bucket, excluidos_por_revisar


# =========================================================
# Snapshot acumulado
# =========================================================

def regenerar_snapshot_saldos_corte(idcliente: int, fecha_corte: str):
    fecha_corte = ultimo_dia_del_mes(fecha_corte)

    # Clientes Alegra migrados a mitad de año fiscal no tienen en
    # auxiliar_contable ningún concepto de saldo acumulado de años
    # anteriores (el Libro Diario cargado normalmente solo cubre el año en
    # curso) - confirmado con datos reales de Maslux LED e Importadora NGC
    # (2026-07-15/18) que sin esto CxC/CxP/patrimonio/retenciones muestran
    # solo el MOVIMIENTO del año cargado, no el saldo real. Si existe un
    # saldo inicial cargado (ver models_alegra.AlegraSaldoInicial,
    # /alegra/cargar_saldos_iniciales) con fecha <= fecha_corte, se usa como
    # piso y se le suma encima solo el movimiento posterior a esa fecha -
    # para Siigo (o Alegra sin saldo inicial cargado) esta tabla
    # simplemente está vacía y el comportamiento es idéntico al de siempre.
    from models_alegra import AlegraSaldoInicial
    fecha_corte_inicial = db.session.query(
        func.max(AlegraSaldoInicial.fecha_corte_inicial)
    ).filter(
        AlegraSaldoInicial.idcliente == idcliente,
        AlegraSaldoInicial.fecha_corte_inicial <= fecha_corte,
    ).scalar()

    if fecha_corte_inicial:
        sql = text("""
            WITH base AS (
                SELECT cuenta_codigo, cuenta_nombre, saldo
                FROM alegra_saldos_iniciales
                WHERE idcliente = :idc AND fecha_corte_inicial = :fci
            ),
            movimiento AS (
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
                    ) AS delta
                FROM auxiliar_contable
                WHERE idcliente = :idc
                  AND fecha_contable > :fci
                  AND fecha_contable <= :fc
                  AND LEFT(cuenta_codigo, 1) IN ('1', '2', '3', '4', '5', '6', '7')
                GROUP BY cuenta_codigo
            )
            SELECT
                COALESCE(b.cuenta_codigo, m.cuenta_codigo) AS cuenta_codigo,
                COALESCE(m.cuenta_nombre, b.cuenta_nombre) AS cuenta_nombre,
                COALESCE(b.saldo, 0) + COALESCE(m.delta, 0) AS saldo
            FROM base b
            FULL OUTER JOIN movimiento m ON m.cuenta_codigo = b.cuenta_codigo
            WHERE COALESCE(b.saldo, 0) + COALESCE(m.delta, 0) <> 0
            ORDER BY 1
        """)
        rows = db.session.execute(sql, {
            "idc": idcliente,
            "fci": fecha_corte_inicial,
            "fc": fecha_corte,
        }).mappings().all()
    else:
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

    rows = list(rows)
    _agregar_filas_sin_codigo_si_es_seguro(rows, idcliente, fecha_corte)

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


def regenerar_snapshot_saldos_corte_desde_balance_prueba(
    idcliente: int,
    periodo_anio: int,
    periodo_mes_inicio: int,
    periodo_mes_fin: int
):
    """
    Construye el snapshot de AuxiliarSaldosCorte a partir del Balance de
    Prueba real descargado de Siigo (tabla BalancePrueba), en vez de
    acumular auxiliar_contable. Reutiliza la misma clasificación contable
    (clasificar_cuenta) que ya usa la ruta de auxiliar_contable, así que
    construir_balance_general no necesita ningún cambio para consumir
    este snapshot.

    Siigo entrega saldo_final con una única convención "débito - crédito"
    para TODAS las clases (confirmado 2026-07-15 contra los estados
    financieros firmados de un cliente real: activo positivo, pasivo y
    patrimonio negativos) — hay que invertir el signo para las clases
    2/3/4 para que coincida con la convención interna de este módulo
    (CREDITO_MENOS_DEBITO), la misma que ya usa el snapshot de auxiliar.

    fecha_corte queda fijada al último día de periodo_mes_fin/periodo_anio
    (la fecha "Saldo final" que reporta Siigo para ese rango).
    """
    fecha_corte = ultimo_dia_del_mes(f"{periodo_anio}-{periodo_mes_fin:02d}-01")

    filas = BalancePrueba.query.filter_by(
        idcliente=idcliente,
        periodo_anio=periodo_anio,
        periodo_mes_inicio=periodo_mes_inicio,
        periodo_mes_fin=periodo_mes_fin,
        es_transaccional=True
    ).all()

    if not filas:
        return {
            "ok": False,
            "error": (
                f"No hay Balance de Prueba cargado para {periodo_anio} "
                f"({periodo_mes_inicio} → {periodo_mes_fin}). Genera y sube "
                f"el archivo desde Siigo primero."
            )
        }

    acumulado = {}
    for fila in filas:
        codigo = str(fila.codigo_cuenta or "").strip()
        if not codigo:
            continue

        meta = clasificar_cuenta(codigo)
        saldo_siigo = safe_float(fila.saldo_final)
        saldo = -saldo_siigo if meta["naturaleza"] == "CREDITO_MENOS_DEBITO" else saldo_siigo

        if codigo not in acumulado:
            acumulado[codigo] = {
                "cuenta_nombre": str(fila.nombre_cuenta or "").strip(),
                "meta": meta,
                "saldo": 0.0,
            }
        acumulado[codigo]["saldo"] += saldo

    AuxiliarSaldosCorte.query.filter_by(
        idcliente=idcliente,
        fecha_corte=fecha_corte
    ).delete()

    inserts = []
    for codigo, datos in acumulado.items():
        if abs(datos["saldo"]) < 0.005:
            continue

        meta = datos["meta"]
        inserts.append(
            AuxiliarSaldosCorte(
                idcliente=idcliente,
                fecha_corte=fecha_corte,
                cuenta_codigo=codigo,
                cuenta_nombre=datos["cuenta_nombre"],
                cuenta_padre=meta["cuenta_padre"],
                clase=meta["clase"],
                grupo=meta["grupo"],
                seccion=meta["seccion"],
                grupo_balance=meta["grupo_balance"],
                naturaleza=meta["naturaleza"],
                saldo=Decimal(str(redondear(datos["saldo"], 2))),
                origen="BALANCE_PRUEBA"
            )
        )

    db.session.bulk_save_objects(inserts)
    db.session.commit()

    return {
        "ok": True,
        "idcliente": idcliente,
        "fecha_corte": fecha_corte,
        "periodo_anio": periodo_anio,
        "periodo_mes_inicio": periodo_mes_inicio,
        "periodo_mes_fin": periodo_mes_fin,
        "registros_generados": len(inserts),
        "origen": "BALANCE_PRUEBA"
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




def _clasificar_alerta_item(item, seccion):
    cuenta = str(item.get("cuenta", ""))
    nombre = str(item.get("nombre", ""))
    saldo = safe_float(item.get("saldo_actual", 0))

    if saldo >= 0:
        return None

    if seccion == "ACTIVO":
        if es_cuenta_contra_activo(cuenta, nombre):
            return {
                "nivel": "info",
                "categoria": "activo_contra_o_ajuste",
                "mensaje": f"La cuenta de activo {cuenta} - {nombre} presenta saldo negativo y parece corresponder a una cuenta contra o de ajuste.",
                "cuenta": cuenta,
                "nombre": nombre,
                "saldo": redondear(saldo, 2),
            }

        if es_cuenta_impuesto_o_retencion(cuenta, nombre):
            return {
                "nivel": "info",
                "categoria": "activo_impuesto_retencion_negativo",
                "mensaje": f"La cuenta de activo {cuenta} - {nombre} presenta saldo negativo; validar si corresponde a devolución, compensación o cruce tributario.",
                "cuenta": cuenta,
                "nombre": nombre,
                "saldo": redondear(saldo, 2),
            }

        if es_cuenta_transitoria_o_legalizacion(cuenta, nombre):
            return {
                "nivel": "warning",
                "categoria": "activo_transitorio_negativo",
                "mensaje": f"La cuenta de activo {cuenta} - {nombre} presenta saldo negativo; conviene revisar su legalización o reclasificación.",
                "cuenta": cuenta,
                "nombre": nombre,
                "saldo": redondear(saldo, 2),
            }

        return {
            "nivel": "warning",
            "categoria": "activo_negativo_otro",
            "mensaje": f"La cuenta de activo {cuenta} - {nombre} presenta saldo negativo; revisar si su naturaleza contable o presentación es correcta.",
            "cuenta": cuenta,
            "nombre": nombre,
            "saldo": redondear(saldo, 2),
        }

    if seccion == "PASIVO":
        # Cuentas como 240810 / 240815 son IVA descontable.
        # Aunque contablemente estén dentro del grupo 24, pueden aparecer con saldo negativo
        # y no deben tratarse como alerta para el usuario.
        if es_cuenta_iva_descontable_presentacion_pasivo(cuenta, nombre):
            return None

        if es_cuenta_contra_pasivo(cuenta, nombre):
            return {
                "nivel": "info",
                "categoria": "pasivo_contra_o_compensacion",
                "mensaje": f"La cuenta de pasivo {cuenta} - {nombre} presenta saldo negativo y podría corresponder a devolución, compensación o cuenta contra.",
                "cuenta": cuenta,
                "nombre": nombre,
                "saldo": redondear(saldo, 2),
            }

        if es_cuenta_impuesto_o_retencion(cuenta, nombre):
            return {
                "nivel": "info",
                "categoria": "pasivo_impuesto_retencion_negativo",
                "mensaje": f"La cuenta de pasivo {cuenta} - {nombre} presenta saldo negativo; validar si corresponde a devolución, compensación tributaria o cuenta de naturaleza especial.",
                "cuenta": cuenta,
                "nombre": nombre,
                "saldo": redondear(saldo, 2),
            }

        return {
            "nivel": "warning",
            "categoria": "pasivo_negativo_otro",
            "mensaje": f"La cuenta de pasivo {cuenta} - {nombre} presenta saldo negativo; revisar si corresponde a la naturaleza esperada de la cuenta.",
            "cuenta": cuenta,
            "nombre": nombre,
            "saldo": redondear(saldo, 2),
        }

    return None

def _label_categoria_alerta(categoria: str):
    labels = {
        "activo_contra_o_ajuste": "Cuentas de activo que parecen contra cuenta o ajuste",
        "activo_impuesto_retencion_negativo": "Activos tributarios/retenciones con saldo negativo",
        "activo_transitorio_negativo": "Activos transitorios o por legalizar con saldo negativo",
        "activo_negativo_otro": "Activos con saldo negativo a revisar",
        "pasivo_contra_o_compensacion": "Pasivos que parecen devolución, compensación o cuenta contra",
        "pasivo_impuesto_retencion_negativo": "Pasivos tributarios/retenciones con saldo negativo",
        "pasivo_negativo_otro": "Pasivos con saldo negativo a revisar",
        "patrimonio_sin_clase_3": "Patrimonio explícito no identificado",
        "ajuste_cuadratura_residual": "Diferencia sin explicar en el balance",
        "snapshot_comparativo_faltante": "Snapshot comparativo faltante",
    }
    return labels.get(categoria, categoria)


def _formatear_muestra_cuentas(items, max_items=6):
    if not items:
        return ""

    partes = []
    for item in items[:max_items]:
        cuenta = str(item.get("cuenta", ""))
        nombre = str(item.get("nombre", ""))
        partes.append(f"{cuenta} {nombre}")

    texto = "; ".join(partes)
    restante = len(items) - max_items
    if restante > 0:
        texto += f"; y {restante} más"

    return texto


def _agrupar_alertas(alertas_dict):
    grupos = defaultdict(list)
    for alerta in alertas_dict:
        categoria = alerta.get("categoria", "otros")
        grupos[categoria].append(alerta)

    alertas_resumen = []
    alertas_grupo = []

    orden = [
        "activo_transitorio_negativo",
        "activo_contra_o_ajuste",
        "activo_impuesto_retencion_negativo",
        "activo_negativo_otro",
        "pasivo_contra_o_compensacion",
        "pasivo_impuesto_retencion_negativo",
        "pasivo_negativo_otro",
        "patrimonio_sin_clase_3",
        "ajuste_cuadratura_residual",
        "snapshot_comparativo_faltante",
    ]

    categorias = [c for c in orden if c in grupos] + [c for c in grupos if c not in orden]

    for categoria in categorias:
        items = grupos[categoria]
        titulo = _label_categoria_alerta(categoria)

        if categoria in ("patrimonio_sin_clase_3", "ajuste_cuadratura_residual", "snapshot_comparativo_faltante"):
            principal = items[0].get("mensaje", titulo)
            alertas_resumen.append(principal)
            alertas_grupo.append({
                "categoria": categoria,
                "titulo": titulo,
                "cantidad": len(items),
                "mensajes": [x.get("mensaje") for x in items],
                "items": items,
            })
            continue

        muestra = _formatear_muestra_cuentas(items, max_items=6)
        mensaje_resumen = f"{titulo}: {len(items)} cuenta(s)."
        if muestra:
            mensaje_resumen += f" Ejemplos: {muestra}."

        alertas_resumen.append(mensaje_resumen)
        alertas_grupo.append({
            "categoria": categoria,
            "titulo": titulo,
            "cantidad": len(items),
            "mensajes": [x.get("mensaje") for x in items],
            "items": items,
        })

    return alertas_resumen, alertas_grupo



def _armar_alertas(
    activo_corriente,
    activo_no_corriente_bruto,
    activo_no_corriente_contra,
    pasivo_corriente,
    pasivo_no_corriente,
    patrimonio_explicito,
    patrimonio_calculado,
    cuadratura_original,
    patrimonio_explicito_total,
    ajuste_cuadratura_residual_actual
):
    alertas = []

    for item in activo_corriente + activo_no_corriente_bruto + activo_no_corriente_contra:
        alerta = _clasificar_alerta_item(item, "ACTIVO")
        if alerta:
            alertas.append(alerta)

    for item in pasivo_corriente + pasivo_no_corriente:
        alerta = _clasificar_alerta_item(item, "PASIVO")
        if alerta:
            alertas.append(alerta)

    if abs(patrimonio_explicito_total) < 1:
        alertas.append({
            "nivel": "warning",
            "categoria": "patrimonio_sin_clase_3",
            "mensaje": "No se identificaron cuentas explícitas de patrimonio clase 3 en el snapshot; el sistema completó el patrimonio con resultado calculado."
        })

    # OJO: ajuste_patrimonio_aplicado_actual combina el resultado del
    # ejercicio (utilidad/pérdida, normal y esperado en CUALQUIER cliente
    # con actividad) con el ajuste_cuadratura_residual_actual (lo que sobra
    # DESPUÉS de sumar ese resultado - una diferencia real, sin explicar,
    # entre lo que dicen las cuentas y lo que dice la caja). Antes esta
    # alerta usaba el combinado, así que disparaba SIEMPRE que hubiera
    # utilidad/pérdida - es decir, casi siempre - y por eso nunca fue una
    # señal útil. Debe evaluar el residual solo (caso real Maslux LED,
    # 2026-09: $52.7M sin explicar, escondidos en silencio en esa línea).
    if abs(ajuste_cuadratura_residual_actual) >= 1:
        alertas.append({
            "nivel": "danger",
            "categoria": "ajuste_cuadratura_residual",
            "mensaje": (
                f"El balance tiene una diferencia de {redondear(ajuste_cuadratura_residual_actual, 2):,.0f} "
                "que no se explica ni con las cuentas cargadas ni con el resultado del ejercicio - el sistema "
                "la muestra como un ajuste de patrimonio para que la ecuación contable cierre, pero es una señal "
                "de un posible error en los datos de origen. Pídele a tu contador que lo revise directamente en Alegra."
            ),
            "monto": redondear(ajuste_cuadratura_residual_actual, 2),
        })

    return alertas


def _armar_narrativa(
    activos_totales,
    pasivos_totales,
    patrimonio_total,
    patrimonio_explicito_total,
    patrimonio_calculado_total,
    activo_no_corriente_bruto_total,
    activo_no_corriente_contra_total,
    activo_no_corriente_neto_total,
    razon_corriente,
    nivel_endeudamiento_pct,
    autonomia_financiera_pct,
    cuadratura_original,
    ajuste_patrimonio_aplicado,
    ajuste_cuadratura_residual,
    modo_comparativo
):
    narrativa = []

    if abs(ajuste_cuadratura_residual) >= 1:
        narrativa.append(
            f"El balance tiene una diferencia de {redondear(ajuste_cuadratura_residual, 2):,.0f} sin explicar "
            "por las cuentas cargadas ni el resultado del ejercicio - revisa la alerta correspondiente."
        )
    elif abs(ajuste_patrimonio_aplicado) < 1:
        narrativa.append("El balance cuadra correctamente al combinar activos, pasivos, patrimonio reportado y resultado acumulado calculado.")
    else:
        narrativa.append("El balance cuadra al sumar el resultado (utilidad o pérdida) del ejercicio al patrimonio.")
    
    if patrimonio_total > 0:
        narrativa.append("La empresa presenta una posición patrimonial positiva.")
    elif patrimonio_total < 0:
        narrativa.append("La empresa presenta patrimonio negativo, lo que indica una situación financiera delicada.")
    else:
        narrativa.append("La empresa no muestra patrimonio neto en el corte evaluado.")

    if abs(patrimonio_calculado_total) >= 1:
        narrativa.append("El patrimonio total combina el patrimonio reportado en cuentas clase 3 con el resultado acumulado calculado desde ingresos, costos y gastos.")

    if abs(activo_no_corriente_contra_total) >= 1:
        narrativa.append(
            f"El activo no corriente se está presentando en forma neta: base por {redondear(activo_no_corriente_bruto_total, 2)} y depreciaciones/ajustes acumulados por {redondear(activo_no_corriente_contra_total, 2)}."
        )

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
    activo_no_corriente_bruto = []
    activo_no_corriente_contra = []
    pasivo_corriente = []
    pasivo_no_corriente = []
    patrimonio_explicito = []
    patrimonio_calculado = []

    utilidad_actual = 0.0
    utilidad_anterior = 0.0

    patrimonio_explicito_actual = 0.0
    patrimonio_explicito_anterior = 0.0

    for row in actuales:
        ant = map_ant.get(row.cuenta_codigo) if modo_comparativo and snapshot_comparativo_existe else None
        item = _crear_item_snapshot(row, ant, modo_comparativo=modo_comparativo and snapshot_comparativo_existe)

        clase = str(row.clase or "")[:1]

        if row.grupo_balance == "ACTIVO_CORRIENTE":
            activo_corriente.append(item)

        elif row.grupo_balance == "ACTIVO_NO_CORRIENTE":
            if es_cuenta_contra_activo(row.cuenta_codigo, row.cuenta_nombre):
                activo_no_corriente_contra.append(item)
            else:
                activo_no_corriente_bruto.append(item)

        elif row.grupo_balance == "PASIVO_CORRIENTE":
            pasivo_corriente.append(item)

        elif row.grupo_balance == "PASIVO_NO_CORRIENTE":
            pasivo_no_corriente.append(item)

        elif row.grupo_balance == "PATRIMONIO":
            patrimonio_explicito.append(item)
            patrimonio_explicito_actual += safe_float(row.saldo)
            patrimonio_explicito_anterior += safe_float(ant.saldo if ant else 0)

        if clase == "4":
            utilidad_actual += safe_float(row.saldo)
            utilidad_anterior += safe_float(ant.saldo if ant else 0)
        elif clase in ("5", "6", "7"):
            utilidad_actual -= safe_float(row.saldo)
            utilidad_anterior -= safe_float(ant.saldo if ant else 0)

    activo_corriente = _ordenar_items(activo_corriente)
    activo_no_corriente_bruto = _ordenar_items(activo_no_corriente_bruto)
    activo_no_corriente_contra = _ordenar_items(activo_no_corriente_contra)
    pasivo_corriente = _ordenar_items(pasivo_corriente)
    pasivo_no_corriente = _ordenar_items(pasivo_no_corriente)
    patrimonio_explicito = _ordenar_items(patrimonio_explicito)

    activo_corriente_total = _total(activo_corriente, "saldo_actual")
    activo_no_corriente_bruto_total = _total(activo_no_corriente_bruto, "saldo_actual")
    activo_no_corriente_contra_total = _total(activo_no_corriente_contra, "saldo_actual")
    activo_no_corriente_total = redondear(activo_no_corriente_bruto_total + activo_no_corriente_contra_total, 2)

    pasivo_corriente_total = _total(pasivo_corriente, "saldo_actual")
    pasivo_no_corriente_total = _total(pasivo_no_corriente, "saldo_actual")

    patrimonio_explicito_total = _total(patrimonio_explicito, "saldo_actual")

    activos_totales = redondear(activo_corriente_total + activo_no_corriente_total, 2)
    pasivos_totales = redondear(pasivo_corriente_total + pasivo_no_corriente_total, 2)

    cuadratura_original = redondear(activos_totales - (pasivos_totales + patrimonio_explicito_total), 2)

    ajuste_patrimonio_aplicado_actual = 0.0
    ajuste_patrimonio_aplicado_anterior = 0.0
    ajuste_cuadratura_residual_actual = 0.0
    ajuste_cuadratura_residual_anterior = 0.0

    patrimonio_calculado_total_actual = 0.0
    patrimonio_calculado_total_anterior = 0.0

    if abs(utilidad_actual) >= 1 or abs(utilidad_anterior) >= 1:
        item_resultado = _crear_item_sintetico(
            cuenta="39RESULTADO",
            nombre="Resultado acumulado calculado desde cuentas 4,5,6,7",
            seccion="PATRIMONIO",
            grupo_balance="PATRIMONIO",
            saldo_actual=utilidad_actual,
            saldo_anterior=utilidad_anterior,
            modo_comparativo=modo_comparativo and snapshot_comparativo_existe
        )
        patrimonio_calculado.append(item_resultado)
        ajuste_patrimonio_aplicado_actual += utilidad_actual
        ajuste_patrimonio_aplicado_anterior += utilidad_anterior
        patrimonio_calculado_total_actual += utilidad_actual
        patrimonio_calculado_total_anterior += utilidad_anterior

    patrimonio_total_temporal = redondear(patrimonio_explicito_total + patrimonio_calculado_total_actual, 2)
    cuadratura_post_resultado = redondear(activos_totales - (pasivos_totales + patrimonio_total_temporal), 2)

    if abs(cuadratura_post_resultado) >= 1:
        item_ajuste = _crear_item_sintetico(
            cuenta="39AJUSTE",
            nombre="Diferencia sin explicar (revisar con tu contador)",
            seccion="PATRIMONIO",
            grupo_balance="PATRIMONIO",
            saldo_actual=cuadratura_post_resultado,
            saldo_anterior=0,
            modo_comparativo=modo_comparativo and snapshot_comparativo_existe
        )
        patrimonio_calculado.append(item_ajuste)

        ajuste_cuadratura_residual_actual = cuadratura_post_resultado
        ajuste_patrimonio_aplicado_actual += cuadratura_post_resultado
        patrimonio_calculado_total_actual += cuadratura_post_resultado

    patrimonio_calculado = _ordenar_items(patrimonio_calculado)

    patrimonio_calculado_total = _total(patrimonio_calculado, "saldo_actual")
    patrimonio_total = redondear(patrimonio_explicito_total + patrimonio_calculado_total, 2)

    patrimonio_total_items = _ordenar_items(patrimonio_explicito + patrimonio_calculado)

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

    alertas_dict = _armar_alertas(
        activo_corriente,
        activo_no_corriente_bruto,
        activo_no_corriente_contra,
        pasivo_corriente,
        pasivo_no_corriente,
        patrimonio_explicito,
        patrimonio_calculado,
        cuadratura_original,
        patrimonio_explicito_actual,
        ajuste_cuadratura_residual_actual
    )

    if modo_comparativo and comparar_con_norm and not snapshot_comparativo_existe:
        alertas_dict.append({
            "nivel": "warning",
            "categoria": "snapshot_comparativo_faltante",
            "mensaje": f"No existe snapshot del corte comparativo {comparar_con_norm}. Se está mostrando solo el balance del corte principal."
        })

    narrativa = _armar_narrativa(
        activos_totales=activos_totales,
        pasivos_totales=pasivos_totales,
        patrimonio_total=patrimonio_total,
        patrimonio_explicito_total=patrimonio_explicito_actual,
        patrimonio_calculado_total=patrimonio_calculado_total_actual,
        activo_no_corriente_bruto_total=activo_no_corriente_bruto_total,
        activo_no_corriente_contra_total=activo_no_corriente_contra_total,
        activo_no_corriente_neto_total=activo_no_corriente_total,
        razon_corriente=razon_corriente,
        nivel_endeudamiento_pct=nivel_endeudamiento_pct,
        autonomia_financiera_pct=autonomia_financiera_pct,
        cuadratura_original=cuadratura_original,
        ajuste_patrimonio_aplicado=ajuste_patrimonio_aplicado_actual,
        ajuste_cuadratura_residual=ajuste_cuadratura_residual_actual,
        modo_comparativo=modo_comparativo and snapshot_comparativo_existe
    )

    alertas_texto, alertas_grupo = _agrupar_alertas(alertas_dict)

    cobertura_alegra = calcular_cobertura_balance_alegra(idcliente, fecha_corte)

    return {
        "ok": True,
        "fechas": {
            "fecha_corte": fecha_corte,
            "comparar_con": comparar_con_norm
        },
        "cobertura": cobertura_alegra,
        "meta": {
            "modo_comparativo": bool(modo_comparativo and snapshot_comparativo_existe),
            "comparacion_solicitada": bool(comparar_con),
            "snapshot_comparativo_existe": snapshot_comparativo_existe,
            "explicacion_filtros": {
                "fecha_corte": "Muestra la situación financiera acumulada hasta esa fecha.",
                "comparar_con": "Permite comparar contra otro corte para analizar variaciones. Se recomienda usar cierres de mes."
            },
            "patrimonio": {
                "patrimonio_explicito_total": redondear(patrimonio_explicito_total, 2),
                "patrimonio_calculado_total": redondear(patrimonio_calculado_total, 2),
                "patrimonio_total": redondear(patrimonio_total, 2),
                "usa_patrimonio_calculado": abs(patrimonio_calculado_total) >= 1
            },
            "activo_no_corriente": {
                "bruto_total": redondear(activo_no_corriente_bruto_total, 2),
                "contra_total": redondear(activo_no_corriente_contra_total, 2),
                "neto_total": redondear(activo_no_corriente_total, 2)
            }
        },
        "kpis": {
            "activo_corriente": activo_corriente_total,
            "activo_no_corriente": activo_no_corriente_total,
            "activo_no_corriente_bruto": activo_no_corriente_bruto_total,
            "activo_no_corriente_contra": activo_no_corriente_contra_total,
            "activos_totales": activos_totales,
            "pasivo_corriente": pasivo_corriente_total,
            "pasivo_no_corriente": pasivo_no_corriente_total,
            "pasivos_totales": pasivos_totales,
            "patrimonio_explicito_total": patrimonio_explicito_total,
            "patrimonio_calculado_total": patrimonio_calculado_total,
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
            "ajuste_patrimonio_aplicado_anterior": redondear(ajuste_patrimonio_aplicado_anterior, 2) if modo_comparativo and snapshot_comparativo_existe else None,
            "ajuste_cuadratura_residual_actual": redondear(ajuste_cuadratura_residual_actual, 2),
            "ajuste_cuadratura_residual_anterior": redondear(ajuste_cuadratura_residual_anterior, 2) if modo_comparativo and snapshot_comparativo_existe else None
        },
        "resumen": {
            "narrativa": narrativa,
            "alertas": alertas_texto,
            "alertas_detalle": alertas_grupo,
            "alertas_detalle_raw": alertas_dict
        },
        "balance": {
            "activo_corriente": activo_corriente,
            "activo_no_corriente_bruto": activo_no_corriente_bruto,
            "activo_no_corriente_contra": activo_no_corriente_contra,
            "activo_no_corriente": _ordenar_items(activo_no_corriente_bruto + activo_no_corriente_contra),
            "pasivo_corriente": pasivo_corriente,
            "pasivo_no_corriente": pasivo_no_corriente,
            "patrimonio_explicito": patrimonio_explicito,
            "patrimonio_calculado": patrimonio_calculado,
            "patrimonio": patrimonio_total_items
        }
    }