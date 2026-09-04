"""
seed_demo_alegra_2026_dinamico.py
=====================================
Script de generación de data demo para InsightsFlow (idcliente = 17,
"InsightsFlow Demo Alegra Comercial S.A.S.") - version Alegra, hermana de
seed_demo_comercial_2026_dinamico.py (idcliente=14, Siigo).

Diferencias clave vs la version Siigo, para que el demo se comporte igual
de "real" que los clientes Alegra que ya validamos esta sesion (Maslux LED,
Importadora NGC):

- Escribe a las tablas alegra_* (models_alegra.py), no siigo_*.
- alegra_facturas/alegra_compras.balance y total_paid quedan INTERNAMENTE
  CONSISTENTES: total = total_paid + monto_aplicado_notas_credito + balance.
  Esto es exactamente lo que confirmamos con datos reales de Alegra (el
  balance ya viene neto de notas credito aplicadas) y lo que ejercita bien
  el fix de "Pagado" de esta sesion (usa total_paid real, no total-saldo).
- Notas credito de venta SI se linkean a facturas reales via
  alegra_nota_credito_facturas.monto_aplicado (tabla puente N:N real de
  Alegra), no solo un total suelto.
- estado de facturas/compras SOLO 'open'/'closed' (nunca 'void'/'draft' -
  no tiene sentido demostrarle a un cliente un problema que ya blindamos).
- Arranca en cero (capital inicial 1-enero, sin alegra_saldos_iniciales) -
  decision explicita: mismo patron que el demo Siigo, sin simular el
  escenario de "saldo inicial migrado a mitad de año".
- No genera dian_documentos (Cruce DIAN queda sin cobertura para este
  cliente demo, igual que el demo Siigo) - decision explicita.

CÓMO USARLO:
    python seed_demo_alegra_2026_dinamico.py

PRE-REQUISITO (ya resuelto para idcliente=17, verificado 2026-07-21):
    - Registro en `clientes` (idcliente=17).
    - Registro en `fuente_datos_cliente` con proveedor='alegra'.
    - Usuario de login (tabla `usuarios`) apuntando a idcliente=17.
    - Paquete/permisos asignados (cliente_paquetes + permisos + perfil_permisos).
    Sin esto, el cliente existe pero nadie puede entrar a verlo ni el
    sistema lo trataria como Alegra.
"""
from dotenv import load_dotenv
load_dotenv()


import os
import uuid
import random
import calendar
from datetime import date, datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP

import psycopg2
from psycopg2.extras import Json


# ─────────────────────────────────────────────
# CONFIGURACIÓN BASE (no modificar)
# ─────────────────────────────────────────────

IDCLIENTE = 17
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("No existe DATABASE_URL en las variables de entorno.")

HOY = date.today()
ANO_ACTUAL = HOY.year
MES_ACTUAL = HOY.month
DIA_ACTUAL = HOY.day

print(f"Ejecutando seed demo Alegra dinámico para fecha: {HOY.strftime('%d/%m/%Y')}")
print(f"Se generará data de enero a {HOY.strftime('%B %Y')} (mes {MES_ACTUAL}).")


# ─────────────────────────────────────────────
# MONTOS BASE POR MES — DINÁMICOS
# ─────────────────────────────────────────────

VENTAS_BASE_CONOCIDAS = {
    1: 72_000_000,
    2: 90_000_000,
    3: 133_000_000,
    4: 101_000_000,
    5: 156_000_000,
}

GASTOS_BASE_CONOCIDOS = {
    1: 49_000_000,
    2: 58_000_000,
    3: 84_000_000,
    4: 67_000_000,
    5: 98_000_000,
}


def estimar_monto_mes(base_conocida: dict, mes_objetivo: int, seed_extra: int = 0) -> int:
    if mes_objetivo in base_conocida:
        return base_conocida[mes_objetivo]

    meses_disponibles = sorted(base_conocida.keys())
    referencia = meses_disponibles[-3:] if len(meses_disponibles) >= 3 else meses_disponibles
    promedio = sum(base_conocida[m] for m in referencia) / len(referencia)

    rng = random.Random(mes_objetivo * 1000 + ANO_ACTUAL + seed_extra)
    factor = rng.uniform(0.88, 1.12)
    estimado = int(promedio * factor)

    base_conocida[mes_objetivo] = estimado
    return estimado


def construir_montos_por_mes() -> tuple[dict, dict]:
    ventas = dict(VENTAS_BASE_CONOCIDAS)
    gastos = dict(GASTOS_BASE_CONOCIDOS)

    for mes in range(1, MES_ACTUAL + 1):
        estimar_monto_mes(ventas, mes, seed_extra=11)
        estimar_monto_mes(gastos, mes, seed_extra=17)

    return ventas, gastos


ventas_base_mes, gastos_base_mes = construir_montos_por_mes()


# ─────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────

def money(value):
    return Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def add_days(fecha, dias):
    return fecha + timedelta(days=dias)


def fin_mes(year, month):
    return date(year, month, calendar.monthrange(year, month)[1])


def dia_maximo_del_mes(mes: int) -> int:
    if mes == MES_ACTUAL:
        return DIA_ACTUAL
    return calendar.monthrange(ANO_ACTUAL, mes)[1]


def fecha_aleatoria_en_mes(mes: int, dia_desde: int = 2) -> date:
    dia_hasta = dia_maximo_del_mes(mes)
    if dia_hasta < dia_desde:
        dia_hasta = dia_desde
    dia = random.randint(dia_desde, dia_hasta)
    return date(ANO_ACTUAL, mes, dia)


def fecha_corte_mes(mes: int) -> date:
    if mes == MES_ACTUAL:
        return HOY
    return fin_mes(ANO_ACTUAL, mes)


def clampear_fecha(fecha: date) -> date:
    return min(fecha, HOY)


# ─────────────────────────────────────────────
# CATÁLOGOS DEMO
# ─────────────────────────────────────────────

# terceros tipo 'cliente' — regimen COMMON_REGIME (empresas que compran)
clientes_demo = [
    ("900211001", "Retail Sabana S.A.S.", "COMMON_REGIME"),
    ("900211002", "Clínica Bienestar Total S.A.S.", "COMMON_REGIME"),
    ("900211003", "Transportes del Pacífico S.A.S.", "COMMON_REGIME"),
    ("900211004", "Constructora Meridiano S.A.S.", "COMMON_REGIME"),
    ("900211005", "Agroindustrias del Valle S.A.S.", "COMMON_REGIME"),
    ("900211006", "Digital Andina Soluciones S.A.S.", "COMMON_REGIME"),
    ("900211007", "Confecciones Real S.A.S.", "COMMON_REGIME"),
    ("900211008", "Constructora Litoral 12 S.A.S.", "COMMON_REGIME"),
]

# proveedores — mezcla de empresa (NIT, COMMON_REGIME) y persona natural
# (cédula, SIMPLIFIED_REGIME), igual que confirmamos con datos reales de
# Maslux/NGC.
proveedores_demo = [
    ("901300001", "Nube Corporativa Colombia S.A.S.", "NIT", "COMMON_REGIME"),
    ("901300002", "Outsourcing Talento BPO S.A.S.", "NIT", "COMMON_REGIME"),
    ("901300003", "Hosting Andino Data S.A.S.", "NIT", "COMMON_REGIME"),
    ("901300004", "Publicidad Capital S.A.S.", "NIT", "COMMON_REGIME"),
    ("901300005", "Transporte Express Andino S.A.S.", "NIT", "COMMON_REGIME"),
    ("901300006", "Asesores Tributarios Andes S.A.S.", "NIT", "COMMON_REGIME"),
    ("901300007", "Arrendamientos del Centro S.A.S.", "NIT", "COMMON_REGIME"),
    ("901300008", "Servicios Generales Beta S.A.S.", "NIT", "COMMON_REGIME"),
    ("1019457781", "Mateo Salazar Prieto", "CC", "SIMPLIFIED_REGIME"),
    ("1024945567", "Ximena Cortés Ríos", "CC", "SIMPLIFIED_REGIME"),
    ("1033457789", "Andrés Felipe Duarte", "CC", "SIMPLIFIED_REGIME"),
]

productos_demo = [
    ("DEMOA-001", "Dashboard Ejecutivo InsightFlow"),
    ("DEMOA-002", "Implementación BI Financiero"),
    ("DEMOA-003", "Soporte Mensual Plataforma"),
    ("DEMOA-004", "Automatización de Reportes"),
    ("DEMOA-005", "Integración API Alegra"),
    ("DEMOA-006", "Consultoría Analítica Empresarial"),
    ("DEMOA-007", "Capacitación Equipo Financiero"),
    ("DEMOA-008", "Paquete Premium de Indicadores"),
]

vendedores_demo = [
    (17001, "Manuela Restrepo"),
    (17002, "Andrés Salcedo"),
    (17003, "Tatiana Rincón"),
    (17004, "Sebastián Cárdenas"),
]

centros_costo_demo = [
    (17101, "ADM", "Administración"),
    (17102, "COM", "Comercial"),
    (17103, "TEC", "Tecnología"),
    (17104, "OPS", "Operaciones"),
]

conceptos_gasto = [
    ("613595", "Costos directos de prestación de servicios tecnológicos"),
    ("613595", "Horas técnicas de implementación y soporte directo"),
    ("513525", "Servicios de hosting y nube"),
    ("511095", "Consultoría tecnológica"),
    ("519595", "Producción de material comercial"),
    ("512010", "Arrendamiento oficina"),
    ("513525", "Servicios administrativos"),
    ("514525", "Mantenimiento de plataforma"),
    ("530505", "Gastos financieros"),
]


# ─────────────────────────────────────────────
# PLAN DE CUENTAS (mismo PUC que el demo Siigo — auxiliar_contable es
# una tabla compartida entre los 2 sistemas, no hace falta reinventarlo)
# ─────────────────────────────────────────────

cuentas = {
    "110505": {"nombre": "Caja general", "tipo": "asset", "nature": "debit"},
    "112005": {"nombre": "Cuenta de ahorro", "tipo": "asset", "nature": "debit"},
    "130505": {"nombre": "Clientes nacionales", "tipo": "asset", "nature": "debit"},
    "135515": {"nombre": "Retención en la fuente a favor", "tipo": "asset", "nature": "debit"},
    "135518": {"nombre": "ReteICA a favor", "tipo": "asset", "nature": "debit"},
    "13551701": {"nombre": "Impuesto a las ventas retenido 15%", "tipo": "asset", "nature": "debit"},
    "152405": {"nombre": "Equipos de oficina", "tipo": "asset", "nature": "debit"},
    "220505": {"nombre": "Proveedores nacionales", "tipo": "liability", "nature": "credit"},
    "233525": {"nombre": "Costos y gastos por pagar", "tipo": "liability", "nature": "credit"},
    "236540": {"nombre": "Retención en la fuente por pagar", "tipo": "liability", "nature": "credit"},
    "236805": {"nombre": "ReteICA por pagar", "tipo": "liability", "nature": "credit"},
    "24080601": {"nombre": "Iva generado servicios 19%", "tipo": "liability", "nature": "credit"},
    "24081501": {"nombre": "Descontable por servicios 19%", "tipo": "liability", "nature": "debit"},
    "250505": {"nombre": "Nómina por pagar", "tipo": "liability", "nature": "credit"},
    "310505": {"nombre": "Capital social", "tipo": "equity", "nature": "credit"},
    "360505": {"nombre": "Utilidad del ejercicio", "tipo": "equity", "nature": "credit"},
    "413595": {"nombre": "Ingresos por servicios tecnológicos", "tipo": "income", "nature": "credit"},
    "417501": {"nombre": "Devoluciones, rebajas y descuentos", "tipo": "income", "nature": "debit"},
    "510506": {"nombre": "Sueldos", "tipo": "expense", "nature": "debit"},
    "511095": {"nombre": "Honorarios", "tipo": "expense", "nature": "debit"},
    "512010": {"nombre": "Arrendamientos", "tipo": "expense", "nature": "debit"},
    "513525": {"nombre": "Servicios", "tipo": "expense", "nature": "debit"},
    "514525": {"nombre": "Mantenimiento", "tipo": "expense", "nature": "debit"},
    "519595": {"nombre": "Gastos diversos", "tipo": "expense", "nature": "debit"},
    "530505": {"nombre": "Gastos financieros", "tipo": "expense", "nature": "debit"},
    "613595": {"nombre": "Costos directos de prestación de servicios tecnológicos", "tipo": "cost", "nature": "debit"},
}


# ─────────────────────────────────────────────
# LIMPIEZA
# ─────────────────────────────────────────────

def limpiar_data_demo(cur):
    print("Limpiando data previa del cliente 17...")

    # Los FKs de las tablas hijas (items/retenciones/puente NC-factura) ya
    # tienen ON DELETE CASCADE hacia su padre (alegra_facturas/alegra_compras/
    # alegra_notas_credito) - borrar el padre ya arrastra al hijo. Se listan
    # igual de forma explícita por claridad, sin depender de eso.
    tablas = [
        "alegra_nota_credito_facturas",
        "alegra_compra_retenciones",
        "alegra_compra_items",
        "alegra_factura_items",
        "alegra_notas_credito",
        "alegra_compras",
        "alegra_facturas",
        "alegra_productos",
        "alegra_terceros",
        "alegra_vendedores",
        "alegra_centros_costo",
        "alegra_cuentas_contables",
        "alegra_retenciones_catalogo",
        "auxiliar_contable",
        "auxiliar_saldos_corte",
    ]
    for tabla in tablas:
        cur.execute(f"DELETE FROM {tabla} WHERE idcliente = %s", (IDCLIENTE,))


# ─────────────────────────────────────────────
# CONFIGURACIONES DASHBOARD
# ─────────────────────────────────────────────

def asegurar_configuraciones(cur):
    print("Validando configuraciones del dashboard e indicadores...")

    cur.execute("SELECT COUNT(*) FROM dashboard_resumen_config WHERE idcliente = %s", (IDCLIENTE,))
    if cur.fetchone()[0] == 0:
        cur.execute(
            """
            INSERT INTO dashboard_resumen_config (
                idcliente, activo, mostrar_caja, mostrar_runway,
                modo_caja, cuentas_incluidas, cuentas_excluidas,
                modo_runway, meses_promedio_runway,
                meta_eficiencia_operativa, meta_ebitda, meta_margen_ebitda,
                meses_grafica, top_clientes, top_proveedores, top_gastos,
                indicador_estrella, modo_periodo_default, creado_en, actualizado_en
            ) VALUES (
                %s, true, true, true,
                'inclusion', '[{"codigo": "11", "nombre": "Caja y Bancos"}]'::jsonb, '[]'::jsonb,
                'egresos_promedio', 3,
                20.00, 35000000, 27.00,
                6, 5, 5, 5,
                'ebitda', 'ytd_cerrado', now(), now()
            )
            """,
            (IDCLIENTE,),
        )

    cur.execute("SELECT COUNT(*) FROM indicadores_financieros_config WHERE idcliente = %s", (IDCLIENTE,))
    if cur.fetchone()[0] == 0:
        cur.execute(
            """
            INSERT INTO indicadores_financieros_config (
                idcliente, activo, liquidez_min, liquidez_max,
                apalancamiento_max, rentabilidad_min, autonomia_min,
                solvencia_min, cobertura_activo_pasivo_min,
                capital_trabajo_min, porcentaje_pasivo_corto_max,
                porcentaje_activo_no_corriente_max,
                endeudamiento_largo_plazo_max,
                creado_por, actualizado_por, created_at, updated_at
            ) VALUES (
                %s, true,
                1.20, 3.00,
                0.65, 0.12, 2.00,
                1.40, 1.20,
                18000000, 0.75,
                0.45, 0.35,
                NULL, NULL, now(), now()
            )
            """,
            (IDCLIENTE,),
        )


# ─────────────────────────────────────────────
# CATÁLOGOS
# ─────────────────────────────────────────────

def insertar_catalogos(cur):
    print("Insertando catálogos Alegra...")

    tercero_seq = 6001
    terceros_clientes = {}   # nombre -> alegra_id
    terceros_proveedores = {}  # nombre -> (alegra_id, tipo_identificacion)

    for nit, nombre, regimen in clientes_demo:
        alegra_id = str(tercero_seq)
        terceros_clientes[nombre] = alegra_id
        cur.execute(
            """
            INSERT INTO alegra_terceros (
                idcliente, alegra_id, nombre, identificacion, tipo,
                regimen, responsabilidades_fiscales, uuid_alegra,
                fecha_sincronizacion
            ) VALUES (
                %s, %s, %s, %s, 'cliente',
                %s, %s, %s,
                now()
            )
            """,
            (IDCLIENTE, alegra_id, nombre, nit, regimen, Json([]), str(uuid.uuid4())),
        )
        tercero_seq += 1

    for nit, nombre, tipo_id, regimen in proveedores_demo:
        alegra_id = str(tercero_seq)
        terceros_proveedores[nombre] = alegra_id
        cur.execute(
            """
            INSERT INTO alegra_terceros (
                idcliente, alegra_id, nombre, identificacion, tipo,
                regimen, responsabilidades_fiscales, uuid_alegra,
                fecha_sincronizacion
            ) VALUES (
                %s, %s, %s, %s, 'proveedor',
                %s, %s, %s,
                now()
            )
            """,
            (IDCLIENTE, alegra_id, nombre, nit, regimen, Json([]), str(uuid.uuid4())),
        )
        tercero_seq += 1

    producto_ids = {}
    prod_seq = 7001
    for code, name in productos_demo:
        alegra_id = str(prod_seq)
        producto_ids[code] = alegra_id
        cur.execute(
            """
            INSERT INTO alegra_productos (
                idcliente, alegra_id, code, name, type,
                categoria_id, cuenta_inventario_id, cuenta_costo_venta_id,
                impuestos, precios, bodegas, fecha_sincronizacion
            ) VALUES (
                %s, %s, %s, %s, 'service',
                NULL, NULL, NULL,
                %s, %s, %s, now()
            )
            """,
            (
                IDCLIENTE, alegra_id, code, name,
                Json([{"name": "IVA", "percentage": 19}]),
                Json([]), Json([]),
            ),
        )
        prod_seq += 1

    for vendedor_id, nombre in vendedores_demo:
        cur.execute(
            """
            INSERT INTO alegra_vendedores (idcliente, alegra_id, nombre, identificacion, activo)
            VALUES (%s, %s, %s, NULL, true)
            """,
            (IDCLIENTE, str(vendedor_id), nombre),
        )

    for centro_id, codigo, nombre in centros_costo_demo:
        cur.execute(
            """
            INSERT INTO alegra_centros_costo (idcliente, alegra_id, nombre, codigo)
            VALUES (%s, %s, %s, %s)
            """,
            (IDCLIENTE, str(centro_id), nombre, codigo),
        )

    # Catálogo de cuentas contables Alegra — mismo PUC usado en auxiliar_contable,
    # necesario para que el selector de "Cuentas incluidas" (Caja Disponible)
    # en Configuraciones Varias pueda buscarlas.
    for codigo, meta in cuentas.items():
        cur.execute(
            """
            INSERT INTO alegra_cuentas_contables (
                idcliente, alegra_id, code, name, type, nature, use,
                category_rule_key, parent_id, fecha_sincronizacion
            ) VALUES (
                %s, %s, %s, %s, %s, %s, 'movement',
                NULL, NULL, now()
            )
            """,
            (IDCLIENTE, codigo, codigo, meta["nombre"], meta["tipo"], meta["nature"]),
        )

    return terceros_clientes, terceros_proveedores, producto_ids


# ─────────────────────────────────────────────
# OPERACIÓN ALEGRA (FACTURAS, NOTAS CRÉDITO Y COMPRAS)
# ─────────────────────────────────────────────

def insertar_operacion_alegra(cur, terceros_clientes, terceros_proveedores, producto_ids):
    print(f"Insertando operación Alegra demo {ANO_ACTUAL} (enero → mes {MES_ACTUAL})...")

    random.seed(ANO_ACTUAL * 10000 + MES_ACTUAL * 100 + DIA_ACTUAL + 5)

    factura_seq = 2001
    compra_seq = 2001
    nota_seq = 2001

    facturas_creadas = []
    compras_creadas = []

    for mes in range(1, MES_ACTUAL + 1):
        es_mes_actual = (mes == MES_ACTUAL)
        dias_mes = calendar.monthrange(ANO_ACTUAL, mes)[1]
        fraccion_mes = DIA_ACTUAL / dias_mes if es_mes_actual else 1.0

        # ── FACTURAS DEL MES ────────────────────────────────────────────
        ventas_mes = ventas_base_mes[mes]
        cantidad_facturas_base = random.randint(9, 13)
        cantidad_facturas = max(1, round(cantidad_facturas_base * fraccion_mes)) if es_mes_actual else cantidad_facturas_base
        promedio_factura = Decimal(ventas_mes) / Decimal(cantidad_facturas_base)

        for i in range(cantidad_facturas):
            cliente_nit, cliente_nombre, _regimen_cli = random.choice(clientes_demo)
            tercero_id = terceros_clientes[cliente_nombre]
            vendedor_id, vendedor_nombre = random.choice(vendedores_demo)
            centro_id, centro_codigo, centro_nombre = random.choice(centros_costo_demo)
            producto_code, producto_name = random.choice(productos_demo)

            fecha = fecha_aleatoria_en_mes(mes)
            # OJO: vencimiento NO se clampea a HOY (a diferencia de fecha/fecha_pago,
            # que si representan algo que ya ocurrio). Un vencimiento SI puede caer
            # despues de hoy - es justo lo que hace que existan cuentas por cobrar
            # "por vencer" en vez de que el 100% de la cartera aparezca vencida
            # (mismo bug real encontrado 2026-09-04 en el script Siigo hermano).
            vencimiento = add_days(fecha, random.choice([15, 30, 45]))

            subtotal = money(promedio_factura * Decimal(str(random.uniform(0.75, 1.32))))
            iva = money(subtotal * Decimal("0.19"))
            total = money(subtotal + iva)

            # Retenciones a favor — no todas las facturas las llevan, depende
            # de si el cliente es agente retenedor. En Alegra la retención
            # reduce balance/total_paid, NUNCA `total` (confirmado con dato
            # real, ver memoria retenciones_iva_correctitud_jul23: `total`
            # de Alegra siempre es bruto, subtotal+impuestos).
            if random.random() <= 0.55:
                retefuente = money(subtotal * Decimal("0.025"))
                reteica = money(subtotal * Decimal("0.00966"))
                reteiva = money(iva * Decimal("0.15"))
            else:
                retefuente = reteica = reteiva = money(0)
            retencion_factura_total = money(retefuente + reteica + reteiva)

            retenciones_factura = []
            if retefuente > 0:
                retenciones_factura.append({"type": "Retención en la fuente por compras", "percentage": 2.5, "value": float(retefuente)})
            if reteica > 0:
                retenciones_factura.append({"type": "RTEICA (9,66X1.000)", "percentage": 0.966, "value": float(reteica)})
            if reteiva > 0:
                retenciones_factura.append({"type": "ReteIVA", "percentage": 15.0, "value": float(reteiva)})

            # ¿Esta factura recibe una nota crédito? (~10%, igual que el demo
            # Siigo).
            monto_nc_aplicado = money(0)
            genera_nc = random.random() <= 0.10
            if genera_nc:
                monto_nc_aplicado = money(total * Decimal(random.choice(["0.05", "0.08", "0.12"])))

            # Monto real por cobrar: total menos lo que ya cubrió la nota
            # crédito y menos lo que el cliente retuvo — pagado/saldo se
            # reparten contra esto, no contra `total` bruto. Mantiene siempre
            # exacta la identidad total = total_paid + nc_aplicada + retencion + saldo.
            monto_por_cubrir = money(total - monto_nc_aplicado - retencion_factura_total)

            # Distribución de pago — igual criterio que el demo Siigo: el mes
            # en curso queda con mas facturas pendientes (aun no vencen).
            umbral_pagada, umbral_parcial = (0.40, 0.65) if es_mes_actual else (0.66, 0.84)
            estado_random = random.random()
            if estado_random <= umbral_pagada:
                total_paid = monto_por_cubrir
                saldo_final = money(0)
            elif estado_random <= umbral_parcial:
                total_paid = money(monto_por_cubrir * Decimal(random.choice(["0.40", "0.55", "0.70"])))
                saldo_final = money(monto_por_cubrir - total_paid)
            else:
                total_paid = money(0)
                saldo_final = monto_por_cubrir

            balance = saldo_final
            estado = "closed" if balance <= 0 else "open"

            alegra_id_factura = str(factura_seq)

            cur.execute(
                """
                INSERT INTO alegra_facturas (
                    idcliente, alegra_id, fecha, vencimiento,
                    tercero_id, tercero_nombre, vendedor_id, centro_costo_id,
                    subtotal, impuestos_total, total, balance, total_paid,
                    estado, moneda, retenciones, payments, stamp,
                    metadata_created, metadata_updated, created_at
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, 'COP', %s, %s, NULL,
                    now(), now(), now()
                ) RETURNING id
                """,
                (
                    IDCLIENTE, alegra_id_factura, fecha, vencimiento,
                    tercero_id, cliente_nombre, str(vendedor_id), str(centro_id),
                    subtotal, iva, total, balance, total_paid,
                    estado, Json(retenciones_factura), Json([]),
                ),
            )
            factura_db_id = cur.fetchone()[0]

            cur.execute(
                """
                INSERT INTO alegra_factura_items (
                    factura_id, idcliente, producto_id, descripcion,
                    cantidad, precio, descuento_valor, total_item, tax
                ) VALUES (%s, %s, %s, %s, 1, %s, 0, %s, %s)
                """,
                (
                    factura_db_id, IDCLIENTE, producto_ids[producto_code], producto_name,
                    subtotal, total,
                    Json([{"type": "IVA", "percentage": 19, "amount": float(iva)}]),
                ),
            )

            if genera_nc:
                nota_alegra_id = str(nota_seq)
                nota_total = monto_nc_aplicado  # nota simple, 1 factura afectada, monto = total de la nota
                nota_subtotal = money(nota_total / Decimal("1.19"))
                nota_iva = money(nota_total - nota_subtotal)

                cur.execute(
                    """
                    INSERT INTO alegra_notas_credito (
                        idcliente, alegra_id, fecha, subtotal, impuestos_total,
                        total, balance, total_applied, cliente_id, estado,
                        stamp, created_at
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, 0, %s, %s, 'open',
                        NULL, now()
                    ) RETURNING id
                    """,
                    (
                        IDCLIENTE, nota_alegra_id,
                        clampear_fecha(add_days(fecha, random.choice([4, 8, 12]))),
                        nota_subtotal, nota_iva, nota_total, nota_total,
                        tercero_id,
                    ),
                )
                nota_db_id = cur.fetchone()[0]

                cur.execute(
                    """
                    INSERT INTO alegra_nota_credito_facturas (
                        idcliente, nota_credito_id, factura_alegra_id, monto_aplicado
                    ) VALUES (%s, %s, %s, %s)
                    """,
                    (IDCLIENTE, nota_db_id, alegra_id_factura, monto_nc_aplicado),
                )
                nota_seq += 1

            facturas_creadas.append({
                "mes": mes,
                "alegra_id": alegra_id_factura,
                "cliente": cliente_nombre,
                "subtotal": subtotal,
                "iva": iva,
                "total": total,
                "balance": balance,
                "total_paid": total_paid,
                "monto_nc_aplicado": monto_nc_aplicado,
                "retefuente": retefuente,
                "reteica": reteica,
                "reteiva": reteiva,
            })
            factura_seq += 1

        # ── COMPRAS DEL MES ──────────────────────────────────────────────
        gastos_mes = gastos_base_mes[mes]
        cantidad_compras_base = random.randint(12, 17)
        cantidad_compras = max(1, round(cantidad_compras_base * fraccion_mes)) if es_mes_actual else cantidad_compras_base
        promedio_compra = Decimal(gastos_mes) / Decimal(cantidad_compras_base)

        for i in range(cantidad_compras):
            proveedor_nit, proveedor_nombre, proveedor_tipo_id, _regimen_prov = random.choice(proveedores_demo)
            proveedor_id = terceros_proveedores[proveedor_nombre]
            centro_id, centro_codigo, centro_nombre = random.choice(centros_costo_demo)
            cuenta_gasto, concepto = random.choice(conceptos_gasto)

            fecha = fecha_aleatoria_en_mes(mes)
            # OJO: vencimiento NO se clampea a HOY (a diferencia de fecha/fecha_pago,
            # que si representan algo que ya ocurrio). Un vencimiento SI puede caer
            # despues de hoy - es justo lo que hace que existan cuentas por cobrar
            # "por vencer" en vez de que el 100% de la cartera aparezca vencida
            # (mismo bug real encontrado 2026-09-04 en el script Siigo hermano).
            vencimiento = add_days(fecha, random.choice([15, 30, 45]))

            subtotal = money(promedio_compra * Decimal(str(random.uniform(0.60, 1.40))))
            iva = money(subtotal * Decimal("0.19"))
            total = money(subtotal + iva)

            # Retenciones practicadas al proveedor — informativo únicamente,
            # vía la tabla real alegra_compra_retenciones (nunca toca
            # total/balance/total_paid).
            if random.random() <= 0.45:
                retefuente_compra = money(subtotal * Decimal("0.04"))
                reteica_compra = money(subtotal * Decimal("0.00966"))
            else:
                retefuente_compra = reteica_compra = money(0)

            umbral_pagada, umbral_parcial = (0.40, 0.65) if es_mes_actual else (0.62, 0.82)
            estado_random = random.random()
            if estado_random <= umbral_pagada:
                total_paid = total
                balance = money(0)
            elif estado_random <= umbral_parcial:
                total_paid = money(total * Decimal(random.choice(["0.40", "0.55", "0.70"])))
                balance = money(total - total_paid)
            else:
                total_paid = money(0)
                balance = total

            estado = "closed" if balance <= 0 else "open"

            # Referencia del proveedor: formato libre, sin guion (confirmado
            # con datos reales de Maslux) - a diferencia de Siigo (FC-.../DS-...).
            factura_proveedor = f"FE{compra_seq}" if proveedor_tipo_id == "NIT" else f"CT{compra_seq}"
            alegra_id_compra = str(compra_seq)

            cur.execute(
                """
                INSERT INTO alegra_compras (
                    idcliente, alegra_id, fecha, vencimiento,
                    proveedor_id, proveedor_nombre, centro_costo_id,
                    factura_proveedor, total, balance, total_paid, estado,
                    created_at
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    now()
                ) RETURNING id
                """,
                (
                    IDCLIENTE, alegra_id_compra, fecha, vencimiento,
                    proveedor_id, proveedor_nombre, str(centro_id),
                    factura_proveedor, total, balance, total_paid, estado,
                ),
            )
            compra_db_id = cur.fetchone()[0]

            cur.execute(
                """
                INSERT INTO alegra_compra_items (
                    compra_id, idcliente, tipo, producto_id, cuenta_contable_id,
                    descripcion, cantidad, precio, subtotal, total, tax
                ) VALUES (%s, %s, 'categoria', NULL, %s, %s, 1, %s, %s, %s, %s)
                """,
                (
                    compra_db_id, IDCLIENTE, cuenta_gasto, concepto,
                    subtotal, subtotal, total,
                    Json([{"type": "IVA", "percentage": 19, "amount": float(iva)}]),
                ),
            )

            if retefuente_compra > 0:
                cur.execute(
                    """
                    INSERT INTO alegra_compra_retenciones (
                        idcliente, compra_id, retention_id, name, percentage,
                        amount, calculated_by, exchange_rate, is_assumed
                    ) VALUES (%s, %s, NULL, %s, %s, %s, 'percentage', NULL, false)
                    """,
                    (IDCLIENTE, compra_db_id, "Retención en la fuente por compras", Decimal("4.0"), retefuente_compra),
                )
            if reteica_compra > 0:
                cur.execute(
                    """
                    INSERT INTO alegra_compra_retenciones (
                        idcliente, compra_id, retention_id, name, percentage,
                        amount, calculated_by, exchange_rate, is_assumed
                    ) VALUES (%s, %s, NULL, %s, %s, %s, 'percentage', NULL, false)
                    """,
                    (IDCLIENTE, compra_db_id, "RTEICA (9,66X1.000)", Decimal("0.966"), reteica_compra),
                )

            compras_creadas.append({
                "mes": mes,
                "alegra_id": alegra_id_compra,
                "proveedor": proveedor_nombre,
                "cuenta_gasto": cuenta_gasto,
                "subtotal": subtotal,
                "iva": iva,
                "total": total,
                "balance": balance,
                "total_paid": total_paid,
                "retefuente_compra": retefuente_compra,
                "reteica_compra": reteica_compra,
            })
            compra_seq += 1

    return facturas_creadas, compras_creadas


# ─────────────────────────────────────────────
# AUXILIAR CONTABLE (misma tabla compartida que usa Siigo)
# ─────────────────────────────────────────────

def insertar_auxiliar(cur, fecha_contable, tipo, numero, cuenta_codigo, tercero_nit, tercero_nombre, detalle, debito=0, credito=0, base=0):
    cuenta = cuentas[cuenta_codigo]
    cur.execute(
        """
        INSERT INTO auxiliar_contable (
            idcliente, fecha_contable,
            comprobante_tipo, comprobante_numero,
            cuenta_codigo, cuenta_nombre,
            tercero_nit, tercero_nombre,
            detalle, debito, credito, base_gravable,
            fecha_carga, archivo_origen,
            periodo_anio, periodo_mes
        ) VALUES (
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            now(), 'seed_demo_alegra_2026_dinamico.py',
            %s, %s
        )
        """,
        (
            IDCLIENTE, fecha_contable,
            tipo, numero,
            cuenta_codigo, cuenta["nombre"],
            tercero_nit, tercero_nombre,
            detalle, money(debito), money(credito), money(base),
            fecha_contable.year, fecha_contable.month,
        ),
    )


def insertar_saldos_corte(cur, fecha_corte, saldos):
    for codigo, saldo in saldos.items():
        if saldo == 0:
            continue

        cuenta = cuentas[codigo]
        cuenta_padre = codigo[:4]
        clase_calc = codigo[:1]
        grupo_calc = codigo[:2]

        if clase_calc == "1":
            seccion_calc = "ACTIVO"
            grupo_balance_calc = "ACTIVO_NO_CORRIENTE" if grupo_calc in ["15", "16", "17"] else "ACTIVO_CORRIENTE"
            naturaleza_calc = "DEBITO_MENOS_CREDITO"
        elif clase_calc == "2":
            seccion_calc = "PASIVO"
            grupo_balance_calc = "PASIVO_CORRIENTE"
            naturaleza_calc = "CREDITO_MENOS_DEBITO"
        elif clase_calc == "3":
            seccion_calc = "PATRIMONIO"
            grupo_balance_calc = "PATRIMONIO"
            naturaleza_calc = "CREDITO_MENOS_DEBITO"
        elif clase_calc == "4":
            seccion_calc = "INGRESOS"
            grupo_balance_calc = "RESULTADO"
            naturaleza_calc = "CREDITO_MENOS_DEBITO"
        elif clase_calc == "5":
            seccion_calc = "GASTOS"
            grupo_balance_calc = "RESULTADO"
            naturaleza_calc = "DEBITO_MENOS_CREDITO"
        elif clase_calc == "6":
            seccion_calc = "COSTOS"
            grupo_balance_calc = "RESULTADO"
            naturaleza_calc = "DEBITO_MENOS_CREDITO"
        else:
            seccion_calc = "OTROS"
            grupo_balance_calc = "OTROS"
            naturaleza_calc = "DEBITO_MENOS_CREDITO"

        saldo_final = money(saldo)

        cur.execute(
            """
            INSERT INTO auxiliar_saldos_corte (
                idcliente, fecha_corte, cuenta_codigo, cuenta_nombre,
                cuenta_padre, clase, grupo, seccion,
                grupo_balance, naturaleza, saldo,
                fecha_generacion, origen
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                now(), 'SEED_DEMO_ALEGRA'
            )
            """,
            (
                IDCLIENTE, fecha_corte,
                codigo, cuenta["nombre"],
                cuenta_padre, clase_calc, grupo_calc, seccion_calc,
                grupo_balance_calc, naturaleza_calc, saldo_final,
            ),
        )


def insertar_contabilidad(cur, facturas, compras):
    print("Insertando auxiliar contable y saldos a corte...")

    saldos = {codigo: money(0) for codigo in cuentas.keys()}

    fecha_inicial = date(ANO_ACTUAL, 1, 1)
    # Aporte inicial: se usa 112005 (Cuenta de ahorro) como cuenta bancaria
    # principal, ya que 111005 no forma parte de este plan de cuentas demo.
    insertar_auxiliar(cur, fecha_inicial, "AP", f"AP-DEMO-ALEGRA-{ANO_ACTUAL}", "112005", None, None, "Aporte inicial en cuenta de ahorro", debito=150_000_000)
    insertar_auxiliar(cur, fecha_inicial, "AP", f"AP-DEMO-ALEGRA-{ANO_ACTUAL}", "152405", None, None, "Equipos de oficina iniciales", debito=30_000_000)
    insertar_auxiliar(cur, fecha_inicial, "AP", f"AP-DEMO-ALEGRA-{ANO_ACTUAL}", "310505", None, None, "Capital social inicial", credito=180_000_000)
    saldos["112005"] += money(150_000_000)
    saldos["152405"] += money(30_000_000)
    saldos["310505"] += money(180_000_000)

    for mes in range(1, MES_ACTUAL + 1):
        fecha_mes = fecha_corte_mes(mes)

        facturas_mes = [f for f in facturas if f["mes"] == mes]
        compras_mes = [c for c in compras if c["mes"] == mes]

        ventas_subtotal = sum((f["subtotal"] for f in facturas_mes), money(0))
        ventas_iva = sum((f["iva"] for f in facturas_mes), money(0))
        ventas_total = sum((f["total"] for f in facturas_mes), money(0))
        ventas_pagadas = sum((f["total_paid"] for f in facturas_mes), money(0))
        ventas_nc_aplicada = sum((f["monto_nc_aplicado"] for f in facturas_mes), money(0))

        # Se suman de las facturas reales del mes (cada una ya trae su propio
        # desglose en alegra_facturas.retenciones), no una tasa plana — así
        # el balance cuadra exacto con lo que se ve factura por factura.
        retencion_favor = sum((f["retefuente"] for f in facturas_mes), money(0))
        reteica_favor = sum((f["reteica"] for f in facturas_mes), money(0))
        reteiva_favor = sum((f["reteiva"] for f in facturas_mes), money(0))
        # Neto en cartera: el total de la factura menos retenciones a favor
        # y menos lo que ya cubrio una nota credito (esa parte nunca fue ni
        # sera un derecho de cobro real).
        valor_clientes_neto = money(
            ventas_total - retencion_favor - reteica_favor - reteiva_favor - ventas_nc_aplicada
        )

        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-ALEGRA-MES-{mes:02d}", "130505", None, "Clientes demo", "Causación ventas demo del mes", debito=valor_clientes_neto, base=ventas_subtotal)
        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-ALEGRA-MES-{mes:02d}", "135515", None, "Clientes demo", "Retención en la fuente a favor por ventas", debito=retencion_favor, base=ventas_subtotal)
        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-ALEGRA-MES-{mes:02d}", "135518", None, "Clientes demo", "ReteICA a favor por ventas", debito=reteica_favor, base=ventas_subtotal)
        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-ALEGRA-MES-{mes:02d}", "13551701", None, "Clientes demo", "ReteIVA a favor por ventas", debito=reteiva_favor, base=ventas_subtotal)
        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-ALEGRA-MES-{mes:02d}", "417501", None, "Clientes demo", "Notas crédito aplicadas a facturas del mes", debito=ventas_nc_aplicada, base=ventas_nc_aplicada)
        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-ALEGRA-MES-{mes:02d}", "413595", None, "Clientes demo", "Ingresos por servicios tecnológicos", credito=ventas_subtotal, base=ventas_subtotal)
        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-ALEGRA-MES-{mes:02d}", "24080601", None, "Clientes demo", "IVA generado servicios 19%", credito=ventas_iva, base=ventas_subtotal)

        saldos["130505"] += valor_clientes_neto
        saldos["135515"] += retencion_favor
        saldos["135518"] += reteica_favor
        saldos["13551701"] += reteiva_favor
        saldos["417501"] += ventas_nc_aplicada
        saldos["413595"] += ventas_subtotal
        saldos["24080601"] += ventas_iva

        insertar_auxiliar(cur, fecha_mes, "RC", f"RC-DEMO-ALEGRA-MES-{mes:02d}", "112005", None, "Clientes demo", "Recaudos recibidos de clientes", debito=ventas_pagadas)
        insertar_auxiliar(cur, fecha_mes, "RC", f"RC-DEMO-ALEGRA-MES-{mes:02d}", "130505", None, "Clientes demo", "Abono de cartera por recaudos", credito=ventas_pagadas)

        saldos["112005"] += ventas_pagadas
        saldos["130505"] -= ventas_pagadas

        compras_subtotal_total = sum((c["subtotal"] for c in compras_mes), money(0))
        compras_iva = sum((c["iva"] for c in compras_mes), money(0))
        compras_total = sum((c["total"] for c in compras_mes), money(0))
        compras_pagadas = sum((c["total_paid"] for c in compras_mes), money(0))

        retencion_pagar = sum((c["retefuente_compra"] for c in compras_mes), money(0))
        reteica_pagar = sum((c["reteica_compra"] for c in compras_mes), money(0))
        proveedor_neto = money(compras_total - retencion_pagar - reteica_pagar)

        costo_directo_mes = money(ventas_subtotal * Decimal("0.24"))
        max_costo_directo = money(compras_subtotal_total * Decimal("0.55"))
        if costo_directo_mes > max_costo_directo:
            costo_directo_mes = max_costo_directo

        gasto_operativo_compras = money(compras_subtotal_total - costo_directo_mes)

        if costo_directo_mes > 0:
            insertar_auxiliar(cur, fecha_mes, "CP", f"CP-DEMO-ALEGRA-MES-{mes:02d}", "613595", None, "Proveedores demo", "Costos directos de prestación de servicios tecnológicos", debito=costo_directo_mes, base=costo_directo_mes)
            saldos["613595"] += costo_directo_mes

        distribucion_gastos = [
            ("511095", Decimal("0.15"), "Honorarios y consultoría"),
            ("512010", Decimal("0.14"), "Arrendamientos"),
            ("513525", Decimal("0.30"), "Servicios operacionales"),
            ("514525", Decimal("0.12"), "Mantenimiento"),
            ("519595", Decimal("0.19"), "Gastos diversos"),
            ("530505", Decimal("0.10"), "Gastos financieros"),
        ]

        acumulado_distribuido = money(0)
        for idx, (cuenta_gasto, porcentaje, descripcion) in enumerate(distribucion_gastos):
            if idx == len(distribucion_gastos) - 1:
                valor = money(gasto_operativo_compras - acumulado_distribuido)
            else:
                valor = money(gasto_operativo_compras * porcentaje)
                acumulado_distribuido += valor

            if valor <= 0:
                continue

            insertar_auxiliar(cur, fecha_mes, "CP", f"CP-DEMO-ALEGRA-MES-{mes:02d}", cuenta_gasto, None, "Proveedores demo", descripcion, debito=valor, base=valor)
            saldos[cuenta_gasto] += valor

        insertar_auxiliar(cur, fecha_mes, "CP", f"CP-DEMO-ALEGRA-MES-{mes:02d}", "24081501", None, "Proveedores demo", "Descontable por servicios 19%", debito=compras_iva, base=compras_subtotal_total)
        insertar_auxiliar(cur, fecha_mes, "CP", f"CP-DEMO-ALEGRA-MES-{mes:02d}", "220505", None, "Proveedores demo", "Cuentas por pagar a proveedores", credito=proveedor_neto, base=compras_subtotal_total)
        insertar_auxiliar(cur, fecha_mes, "CP", f"CP-DEMO-ALEGRA-MES-{mes:02d}", "236540", None, "Proveedores demo", "Retención en la fuente por pagar", credito=retencion_pagar, base=compras_subtotal_total)
        insertar_auxiliar(cur, fecha_mes, "CP", f"CP-DEMO-ALEGRA-MES-{mes:02d}", "236805", None, "Proveedores demo", "ReteICA por pagar", credito=reteica_pagar, base=compras_subtotal_total)

        saldos["24081501"] += compras_iva
        saldos["220505"] += proveedor_neto
        saldos["236540"] += retencion_pagar
        saldos["236805"] += reteica_pagar

        insertar_auxiliar(cur, fecha_mes, "PP", f"PP-DEMO-ALEGRA-MES-{mes:02d}", "220505", None, "Proveedores demo", "Pagos realizados a proveedores", debito=compras_pagadas)
        insertar_auxiliar(cur, fecha_mes, "PP", f"PP-DEMO-ALEGRA-MES-{mes:02d}", "112005", None, "Proveedores demo", "Salida de banco por pagos a proveedores", credito=compras_pagadas)

        saldos["220505"] -= compras_pagadas
        saldos["112005"] -= compras_pagadas

        ingresos = saldos["413595"] - saldos["417501"]
        costos = saldos["613595"]
        gastos = (
            saldos["510506"] + saldos["511095"] + saldos["512010"]
            + saldos["513525"] + saldos["514525"] + saldos["519595"]
            + saldos["530505"]
        )
        utilidad = money(ingresos - costos - gastos)
        saldos["360505"] = utilidad

        insertar_saldos_corte(cur, fecha_corte_mes(mes), saldos)


# ─────────────────────────────────────────────
# VALIDACIÓN / RESUMEN FINAL
# ─────────────────────────────────────────────

def validar(cur):
    print("\n── Resumen final (Alegra demo, idcliente=17) ──────────────────")

    consultas = [
        ("Terceros",         "SELECT COUNT(*), 0, 0 FROM alegra_terceros WHERE idcliente = 17"),
        ("Productos",        "SELECT COUNT(*), 0, 0 FROM alegra_productos WHERE idcliente = 17"),
        ("Cuentas contables","SELECT COUNT(*), 0, 0 FROM alegra_cuentas_contables WHERE idcliente = 17"),
        ("Facturas",         "SELECT COUNT(*), COALESCE(SUM(total),0), COALESCE(SUM(balance),0) FROM alegra_facturas WHERE idcliente = 17"),
        ("Notas crédito",    "SELECT COUNT(*), COALESCE(SUM(total),0), 0 FROM alegra_notas_credito WHERE idcliente = 17"),
        ("NC aplicadas",     "SELECT COUNT(*), COALESCE(SUM(monto_aplicado),0), 0 FROM alegra_nota_credito_facturas WHERE idcliente = 17"),
        ("Compras",          "SELECT COUNT(*), COALESCE(SUM(total),0), COALESCE(SUM(balance),0) FROM alegra_compras WHERE idcliente = 17"),
        ("Retenciones ventas", "SELECT COUNT(*), COALESCE(SUM((elem->>'value')::numeric),0), 0 FROM alegra_facturas, jsonb_array_elements(retenciones::jsonb) elem WHERE idcliente = 17"),
        ("Retenciones compras", "SELECT COUNT(*), COALESCE(SUM(amount),0), 0 FROM alegra_compra_retenciones WHERE idcliente = 17"),
        ("Auxiliar contable","SELECT COUNT(*), COALESCE(SUM(debito),0), COALESCE(SUM(credito),0) FROM auxiliar_contable WHERE idcliente = 17"),
        ("Saldos corte",     "SELECT COUNT(*), COALESCE(SUM(saldo),0), 0 FROM auxiliar_saldos_corte WHERE idcliente = 17"),
    ]

    for nombre, sql in consultas:
        cur.execute(sql)
        a, b, c = cur.fetchone()
        print(f"  {nombre:<22} registros={a:>4}  total_1={b:>18}  total_2={c:>18}")

    # Chequeo de consistencia interna: total = total_paid + monto_nc_aplicado
    # + retencion_aplicada + balance (mismo criterio que usamos toda la
    # sesion para validar clientes reales, extendido con retenciones)
    cur.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT
                af.id,
                af.total,
                af.total_paid,
                af.balance,
                af.retenciones,
                COALESCE(SUM(ncf.monto_aplicado), 0) AS nc_aplicada,
                COALESCE((
                    SELECT SUM((elem->>'value')::numeric)
                    FROM jsonb_array_elements(af.retenciones) elem
                    WHERE jsonb_typeof(af.retenciones) = 'array'
                ), 0) AS retencion_aplicada
            FROM alegra_facturas af
            LEFT JOIN alegra_nota_credito_facturas ncf
                ON ncf.idcliente = af.idcliente AND ncf.factura_alegra_id = af.alegra_id
            WHERE af.idcliente = 17
            GROUP BY af.id, af.total, af.total_paid, af.balance, af.retenciones
        ) t
        WHERE ABS(t.total - t.total_paid - t.balance - t.nc_aplicada - t.retencion_aplicada) > 0.02
        """
    )
    inconsistentes = cur.fetchone()[0]
    print(f"\n  Facturas con total != total_paid + saldo + nota_aplicada + retencion: {inconsistentes} (debe ser 0)")

    print("\nVentas por mes:")
    cur.execute(
        """
        SELECT DATE_TRUNC('month', fecha)::date AS mes,
               COUNT(*) AS facturas,
               SUM(subtotal) AS subtotal,
               SUM(total) AS total,
               SUM(balance) AS saldo
        FROM alegra_facturas WHERE idcliente = 17
        GROUP BY 1 ORDER BY 1
        """
    )
    for row in cur.fetchall():
        print(f"  {row}")

    print("\nCompras por mes:")
    cur.execute(
        """
        SELECT DATE_TRUNC('month', fecha)::date AS mes,
               COUNT(*) AS compras,
               SUM(total) AS total,
               SUM(balance) AS saldo
        FROM alegra_compras WHERE idcliente = 17
        GROUP BY 1 ORDER BY 1
        """
    )
    for row in cur.fetchall():
        print(f"  {row}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn:
            with conn.cursor() as cur:
                limpiar_data_demo(cur)
                asegurar_configuraciones(cur)
                terceros_clientes, terceros_proveedores, producto_ids = insertar_catalogos(cur)
                facturas, compras = insertar_operacion_alegra(cur, terceros_clientes, terceros_proveedores, producto_ids)
                insertar_contabilidad(cur, facturas, compras)
                validar(cur)

        print(f"\n✓ Carga demo Alegra dinámica finalizada — data actualizada al {HOY.strftime('%d/%m/%Y')}.")

    except Exception as e:
        conn.rollback()
        print("\n✗ ERROR. Se hizo rollback. No quedó data parcial.")
        raise e
    finally:
        conn.close()


if __name__ == "__main__":
    main()
