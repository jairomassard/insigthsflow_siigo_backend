import os
import uuid
import random
import calendar
from datetime import date, datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP

import psycopg2
from psycopg2.extras import Json


IDCLIENTE = 14
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("No existe DATABASE_URL en las variables de entorno.")


def money(value):
    return Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def d(year, month, day):
    return date(year, month, day)


def add_days(fecha, dias):
    return fecha + timedelta(days=dias)


def fin_mes(year, month):
    return date(year, month, calendar.monthrange(year, month)[1])


clientes_demo = [
    ("900111001", "Andes Retail Group S.A.S.", "contabilidad@andesretaildemo.com"),
    ("900111002", "Nova Salud Empresarial S.A.S.", "financiera@novasaluddemo.com"),
    ("900111003", "Logística Horizonte S.A.S.", "pagos@logisticahorizontedemo.com"),
    ("900111004", "Grupo Inmobiliario Capital S.A.S.", "contabilidad@inmocapitaldemo.com"),
    ("900111005", "Energía Verde Colombia S.A.S.", "tesoreria@energiaverdedemo.com"),
    ("900111006", "TecnoSoluciones Latam S.A.S.", "finanzas@tecnolatamdemo.com"),
    ("900111007", "Alimentos Vitales S.A.S.", "cartera@alimentosvitalesdemo.com"),
    ("900111008", "Constructora Norte 45 S.A.S.", "proveedores@constructoranorte45demo.com"),
]

proveedores_demo = [
    # Proveedores empresa: generan facturas de compra FC
    ("901200001", "Cloud Services Colombia S.A.S.", "NIT", "Bogotá"),
    ("901200002", "Talento Creativo BPO S.A.S.", "NIT", "Bogotá"),
    ("901200003", "Data Hosting Latam S.A.S.", "NIT", "Medellín"),
    ("901200004", "Impresos Capital S.A.S.", "NIT", "Bogotá"),
    ("901200005", "Logística Express Andina S.A.S.", "NIT", "Cali"),
    ("901200006", "Consultores Tributarios Pro S.A.S.", "NIT", "Bogotá"),
    ("901200007", "Arrendamientos Corporativos S.A.S.", "NIT", "Bogotá"),
    ("901200008", "Servicios Generales Alfa S.A.S.", "NIT", "Barranquilla"),

    # Personas naturales: generan documentos soporte DS / cuentas de cobro
    ("1018457781", "Nicolás Herrera", "Cedula de ciudadania", "Bogotá"),
    ("1023945567", "Valeria Ríos", "Cedula de ciudadania", "Bogotá"),
    ("1032457789", "Juan Camilo Duarte", "Cedula de ciudadania", "Medellín"),
]

productos_demo = [
    ("DEMO-001", "Dashboard Ejecutivo InsightFlow"),
    ("DEMO-002", "Implementación BI Financiero"),
    ("DEMO-003", "Soporte Mensual Plataforma"),
    ("DEMO-004", "Automatización de Reportes"),
    ("DEMO-005", "Integración API Siigo"),
    ("DEMO-006", "Consultoría Analítica Empresarial"),
    ("DEMO-007", "Capacitación Equipo Financiero"),
    ("DEMO-008", "Paquete Premium de Indicadores"),
]

vendedores_demo = [
    (14001, "Laura Méndez"),
    (14002, "Carlos Rivas"),
    (14003, "Paula Santamaría"),
    (14004, "Miguel Torres"),
]

centros_costo_demo = [
    (14101, "ADM", "Administración"),
    (14102, "COM", "Comercial"),
    (14103, "TEC", "Tecnología"),
    (14104, "OPS", "Operaciones"),
]

empleados_demo = [
    ("Ana María Gómez", "1020304010", "CT-DEMO-001", 5800000),
    ("Julián Pérez", "1020304011", "CT-DEMO-002", 6400000),
    ("Camila Rojas", "1020304012", "CT-DEMO-003", 5200000),
    ("Felipe Andrade", "1020304013", "CT-DEMO-004", 7300000),
    ("Daniela Castro", "1020304014", "CT-DEMO-005", 4900000),
]

ventas_base_mes = {
    1: 85000000,
    2: 98000000,
    3: 121000000,
    4: 109000000,
    5: 148000000,
}

gastos_base_mes = {
    1: 58000000,
    2: 65000000,
    3: 78000000,
    4: 74000000,
    5: 92000000,
}


cuentas = {
    "110505": {
        "nombre": "Caja general",
        "clase": "1",
        "grupo": "Disponible",
        "seccion": "ACTIVO",
        "grupo_balance": "Caja y bancos",
        "naturaleza": "debito",
    },
    "111005": {
        "nombre": "Bancos nacionales",
        "clase": "1",
        "grupo": "Disponible",
        "seccion": "ACTIVO",
        "grupo_balance": "Caja y bancos",
        "naturaleza": "debito",
    },
    "130505": {
        "nombre": "Clientes nacionales",
        "clase": "1",
        "grupo": "Deudores",
        "seccion": "ACTIVO",
        "grupo_balance": "Cuentas por cobrar",
        "naturaleza": "debito",
    },
    "135515": {
        "nombre": "Retención en la fuente a favor",
        "clase": "1",
        "grupo": "Anticipos de impuestos",
        "seccion": "ACTIVO",
        "grupo_balance": "Impuestos a favor",
        "naturaleza": "debito",
    },
    "135518": {
        "nombre": "ReteICA a favor",
        "clase": "1",
        "grupo": "Anticipos de impuestos",
        "seccion": "ACTIVO",
        "grupo_balance": "Impuestos a favor",
        "naturaleza": "debito",
    },
    "13551701": {
        "nombre": "Impuesto a las ventas retenido 15%",
        "clase": "1",
        "grupo": "Anticipos de impuestos",
        "seccion": "ACTIVO",
        "grupo_balance": "Impuestos a favor",
        "naturaleza": "debito",
    },
    "152405": {
        "nombre": "Equipos de oficina",
        "clase": "1",
        "grupo": "Propiedad planta y equipo",
        "seccion": "ACTIVO",
        "grupo_balance": "Activos fijos",
        "naturaleza": "debito",
    },
    "220505": {
        "nombre": "Proveedores nacionales",
        "clase": "2",
        "grupo": "Proveedores",
        "seccion": "PASIVO",
        "grupo_balance": "Cuentas por pagar",
        "naturaleza": "credito",
    },
    "233525": {
        "nombre": "Costos y gastos por pagar",
        "clase": "2",
        "grupo": "Cuentas por pagar",
        "seccion": "PASIVO",
        "grupo_balance": "Gastos por pagar",
        "naturaleza": "credito",
    },
    "236540": {
        "nombre": "Retención en la fuente por pagar",
        "clase": "2",
        "grupo": "Retenciones por pagar",
        "seccion": "PASIVO",
        "grupo_balance": "Impuestos por pagar",
        "naturaleza": "credito",
    },
    "236805": {
        "nombre": "ReteICA por pagar",
        "clase": "2",
        "grupo": "Retenciones por pagar",
        "seccion": "PASIVO",
        "grupo_balance": "Impuestos por pagar",
        "naturaleza": "credito",
    },
    "24080601": {
        "nombre": "Iva generado servicios 19%",
        "clase": "2",
        "grupo": "Impuestos por pagar",
        "seccion": "PASIVO",
        "grupo_balance": "IVA",
        "naturaleza": "credito",
    },
    "24081501": {
        "nombre": "Descontable por servicios 19%",
        "clase": "2",
        "grupo": "Impuestos descontables",
        "seccion": "PASIVO",
        "grupo_balance": "IVA descontable",
        "naturaleza": "debito",
    },
    "240805": {
        "nombre": "IVA generado",
        "clase": "2",
        "grupo": "Impuestos por pagar",
        "seccion": "PASIVO",
        "grupo_balance": "IVA",
        "naturaleza": "credito",
    },
    "240810": {
        "nombre": "IVA descontable",
        "clase": "2",
        "grupo": "Impuestos descontables",
        "seccion": "Activo corriente",
        "grupo_balance": "IVA descontable",
        "naturaleza": "debito",
    },
    "250505": {
        "nombre": "Nómina por pagar",
        "clase": "2",
        "grupo": "Obligaciones laborales",
        "seccion": "Pasivo corriente",
        "grupo_balance": "Obligaciones laborales",
        "naturaleza": "credito",
    },
    "310505": {
        "nombre": "Capital social",
        "clase": "3",
        "grupo": "Capital social",
        "seccion": "PATRIMONIO",
        "grupo_balance": "Patrimonio",
        "naturaleza": "credito",
    },
    "360505": {
        "nombre": "Utilidad del ejercicio",
        "clase": "3",
        "grupo": "Resultados",
        "seccion": "PATRIMONIO",
        "grupo_balance": "Resultado del ejercicio",
        "naturaleza": "credito",
    },
    "413595": {
        "nombre": "Ingresos por servicios tecnológicos",
        "clase": "4",
        "grupo": "Ingresos operacionales",
        "seccion": "Estado de resultados",
        "grupo_balance": "Ingresos",
        "naturaleza": "credito",
    },
    "417501": {
        "nombre": "Devoluciones, rebajas y descuentos",
        "clase": "4",
        "grupo": "Devoluciones",
        "seccion": "Estado de resultados",
        "grupo_balance": "Menor ingreso",
        "naturaleza": "debito",
    },
    "510506": {
        "nombre": "Sueldos",
        "clase": "5",
        "grupo": "Gastos de personal",
        "seccion": "Estado de resultados",
        "grupo_balance": "Gastos operacionales",
        "naturaleza": "debito",
    },
    "511095": {
        "nombre": "Honorarios",
        "clase": "5",
        "grupo": "Honorarios",
        "seccion": "Estado de resultados",
        "grupo_balance": "Gastos operacionales",
        "naturaleza": "debito",
    },
    "512010": {
        "nombre": "Arrendamientos",
        "clase": "5",
        "grupo": "Arrendamientos",
        "seccion": "Estado de resultados",
        "grupo_balance": "Gastos operacionales",
        "naturaleza": "debito",
    },
    "513525": {
        "nombre": "Servicios",
        "clase": "5",
        "grupo": "Servicios",
        "seccion": "Estado de resultados",
        "grupo_balance": "Gastos operacionales",
        "naturaleza": "debito",
    },
    "514525": {
        "nombre": "Mantenimiento",
        "clase": "5",
        "grupo": "Mantenimiento",
        "seccion": "Estado de resultados",
        "grupo_balance": "Gastos operacionales",
        "naturaleza": "debito",
    },
    "519595": {
        "nombre": "Gastos diversos",
        "clase": "5",
        "grupo": "Diversos",
        "seccion": "Estado de resultados",
        "grupo_balance": "Gastos operacionales",
        "naturaleza": "debito",
    },
    "530505": {
        "nombre": "Gastos financieros",
        "clase": "5",
        "grupo": "Financieros",
        "seccion": "Estado de resultados",
        "grupo_balance": "Gastos no operacionales",
        "naturaleza": "debito",
    },
}


def limpiar_data_demo(cur):
    print("Limpiando data previa del cliente 14...")

    tablas = [
        "siigo_pagos_recibidos",
        "siigo_pagos_proveedores",
        "siigo_cuentasporcobrar",
        "siigo_factura_items",
        "siigo_notas_credito",
        "siigo_facturas",
        "siigo_compras_items",
        "siigo_compras_ajustes",
        "siigo_compras",
        "siigo_nomina",
        "siigo_productos",
        "siigo_customers",
        "siigo_proveedores",
        "siigo_vendedores",
        "siigo_centros_costo",
        "auxiliar_contable",
        "auxiliar_saldos_corte",
        "balance_prueba",
    ]

    for tabla in tablas:
        cur.execute(f"DELETE FROM {tabla} WHERE idcliente = %s", (IDCLIENTE,))


def asegurar_configuraciones(cur):
    print("Validando configuraciones del dashboard e indicadores...")

    cur.execute(
        """
        SELECT COUNT(*)
        FROM dashboard_resumen_config
        WHERE idcliente = %s
        """,
        (IDCLIENTE,),
    )

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
            )
            VALUES (
                %s, true, true, true,
                'inclusion', '["110505", "111005"]'::jsonb, '[]'::jsonb,
                'egresos_promedio', 3,
                20.00, 40000000, 28.00,
                6, 5, 5, 5,
                'ebitda', 'ytd_cerrado', now(), now()
            )
            """,
            (IDCLIENTE,),
        )

    cur.execute(
        """
        SELECT COUNT(*)
        FROM indicadores_financieros_config
        WHERE idcliente = %s
        """,
        (IDCLIENTE,),
    )

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
                creado_por, actualizado_por,
                created_at, updated_at
            )
            VALUES (
                %s, true,
                1.20, 3.00,
                0.65, 0.12, 2.00,
                1.40, 1.20,
                20000000, 0.75,
                0.45, 0.35,
                NULL, NULL,
                now(), now()
            )
            """,
            (IDCLIENTE,),
        )


def insertar_catalogos(cur):
    print("Insertando catálogos...")

    customer_ids = {}
    producto_ids = {}

    for nit, nombre, email in clientes_demo:
        customer_uuid = str(uuid.uuid4())
        customer_ids[nombre] = {
            "uuid": customer_uuid,
            "nit": nit,
            "email": email,
        }

        cur.execute(
            """
            INSERT INTO siigo_customers (
                id, idcliente, identification, name, first_name, last_name,
                branch_office, email, phone, address, contacts, metadata,
                created_at, updated_at
            )
            VALUES (
                %s, %s, %s, %s, NULL, NULL,
                0, %s, %s, %s, %s, %s,
                now(), now()
            )
            """,
            (
                customer_uuid,
                IDCLIENTE,
                nit,
                nombre,
                email,
                "6013000000",
                Json({"city": "Bogotá", "address": "Dirección comercial demo"}),
                Json([]),
                Json({"demo": True, "tipo": "cliente_comercial"}),
            ),
        )

    for code, name in productos_demo:
        producto_uuid = str(uuid.uuid4())
        producto_ids[code] = producto_uuid

        cur.execute(
            """
            INSERT INTO siigo_productos (
                id, idcliente, code, name, type,
                account_group_id, account_group_name,
                unit_code, unit_name, unit_label,
                tax_classification, tax_included, active,
                stock_control, available_quantity,
                taxes, warehouses, additional_fields,
                metadata_created, metadata_updated
            )
            VALUES (
                %s, %s, %s, %s, 'Service',
                1, 'Servicios',
                '94', 'Unidad', 'Unidad',
                'IVA', false, true,
                false, 0,
                %s, %s, %s,
                now(), now()
            )
            """,
            (
                producto_uuid,
                IDCLIENTE,
                code,
                name,
                Json([{"name": "IVA", "percentage": 19}]),
                Json([]),
                Json({"demo": True}),
            ),
        )

    for nit, nombre, tipo_identificacion, ciudad in proveedores_demo:
        cur.execute(
            """
            INSERT INTO siigo_proveedores (
                idcliente, nombre, tipo_identificacion, identificacion,
                digito_verificacion, direccion, ciudad, telefono, estado, created_at
            )
            VALUES (
                %s, %s, %s, %s,
                '0', 'Dirección proveedor demo', %s, '6014000000', 'Activo', now()
            )
            """,
            (IDCLIENTE, nombre, tipo_identificacion, nit, ciudad),
        )

    for vendedor_id, nombre in vendedores_demo:
        cur.execute(
            """
            INSERT INTO siigo_vendedores (
                id, nombre, activo, metadata, idcliente
            )
            VALUES (%s, %s, true, %s, %s)
            """,
            (vendedor_id, nombre, Json({"demo": True}), IDCLIENTE),
        )

    for centro_id, codigo, nombre in centros_costo_demo:
        cur.execute(
            """
            INSERT INTO siigo_centros_costo (
                id, nombre, codigo, activo, metadata, idcliente
            )
            VALUES (%s, %s, %s, true, %s, %s)
            """,
            (centro_id, nombre, codigo, Json({"demo": True}), IDCLIENTE),
        )

    return customer_ids, producto_ids


def insertar_operacion_siigo(cur, customer_ids, producto_ids):
    print("Insertando operación Siigo demo 2026...")

    random.seed(20260608)

    factura_seq = 1001
    compra_seq = 1001
    pago_recibido_seq = 1001
    pago_proveedor_seq = 1001
    nota_seq = 1001

    facturas_creadas = []
    compras_creadas = []

    for mes in range(1, 6):
        ventas_mes = ventas_base_mes[mes]
        cantidad_facturas = random.randint(9, 13)
        promedio_factura = Decimal(ventas_mes) / Decimal(cantidad_facturas)

        for i in range(cantidad_facturas):
            cliente_nit, cliente_nombre, cliente_email = random.choice(clientes_demo)
            vendedor_id, vendedor_nombre = random.choice(vendedores_demo)
            centro_id, centro_codigo, centro_nombre = random.choice(centros_costo_demo)
            producto_code, producto_name = random.choice(productos_demo)

            fecha = d(2026, mes, random.randint(2, 25))
            vencimiento = add_days(fecha, random.choice([15, 30, 45]))

            subtotal = money(promedio_factura * Decimal(str(random.uniform(0.75, 1.32))))
            iva = money(subtotal * Decimal("0.19"))
            total = money(subtotal + iva)

            estado_random = random.random()

            if estado_random <= 0.66:
                estado_pago = "pagada"
                pagos_total = total
                saldo = money(0)
            elif estado_random <= 0.84:
                estado_pago = "parcial"
                pagos_total = money(total * Decimal(random.choice(["0.40", "0.55", "0.70"])))
                saldo = money(total - pagos_total)
            else:
                estado_pago = "pendiente"
                pagos_total = money(0)
                saldo = total

            idfactura = f"FV-9-{factura_seq}"

            cur.execute(
                """
                INSERT INTO siigo_facturas (
                    idcliente, idfactura, fecha, vencimiento,
                    cliente_nombre, vendedor, estado,
                    total, saldo, created_at,
                    siigo_uuid, customer_id, customer_identificacion,
                    seller_id, moneda, subtotal, impuestos_total,
                    descuentos_total, pagos_total, saldo_calculado,
                    estado_pago, medio_pago, observaciones,
                    metadata_created, metadata_updated, public_url,
                    cost_center, retenciones
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s, 'Emitida',
                    %s, %s, now(),
                    %s, %s, %s,
                    %s, 'COP', %s, %s,
                    0, %s, %s,
                    %s, %s, %s,
                    now(), now(), %s,
                    %s, %s
                )
                RETURNING id
                """,
                (
                    IDCLIENTE,
                    idfactura,
                    fecha,
                    vencimiento,
                    cliente_nombre,
                    vendedor_nombre,
                    total,
                    saldo,
                    str(uuid.uuid4()),
                    customer_ids[cliente_nombre]["uuid"],
                    cliente_nit,
                    vendedor_id,
                    subtotal,
                    iva,
                    pagos_total,
                    saldo,
                    estado_pago,
                    random.choice(["TRANSF", "PSE", "CONSIG"]),
                    "Factura demo generada para videos comerciales de InsightsFlow.",
                    f"https://demo.insightsflow.com/facturas/{idfactura}",
                    centro_id,
                    Json([]),
                ),
            )

            factura_db_id = cur.fetchone()[0]

            cur.execute(
                """
                INSERT INTO siigo_factura_items (
                    factura_id, descripcion, cantidad, precio,
                    impuestos, producto_id, codigo, sku,
                    iva_porcentaje, iva_valor, descuento_valor,
                    total_item, retenciones_item, idcliente
                )
                VALUES (
                    %s, %s, 1, %s,
                    %s, %s, %s, %s,
                    19, %s, 0,
                    %s, %s, %s
                )
                """,
                (
                    factura_db_id,
                    producto_name,
                    subtotal,
                    iva,
                    producto_code,
                    producto_code,
                    producto_code,
                    iva,
                    total,
                    Json([]),
                    IDCLIENTE,
                ),
            )

            if pagos_total > 0:
                fecha_pago = min(add_days(fecha, random.choice([5, 12, 20, 32])), d(2026, 5, 31))

                cur.execute(
                    """
                    INSERT INTO siigo_pagos_recibidos (
                        idcliente, idpago, fecha, cliente_nombre,
                        metodo_pago, valor, factura_aplicada, created_at
                    )
                    VALUES (
                        %s, %s, %s, %s,
                        %s, %s, %s, now()
                    )
                    """,
                    (
                        IDCLIENTE,
                        f"RC-9-{pago_recibido_seq}",
                        fecha_pago,
                        cliente_nombre,
                        random.choice(["TRANSF", "PSE", "CONSIG"]),
                        pagos_total,
                        idfactura,
                    ),
                )
                pago_recibido_seq += 1

            if saldo > 0:
                cur.execute(
                    """
                    INSERT INTO siigo_cuentasporcobrar (
                        idcliente, documento, fecha, fecha_vencimiento,
                        proveedor_identificacion, proveedor_nombre,
                        valor, saldo, centro_costo, idcompra, created_at
                    )
                    VALUES (
                        %s, %s, %s, %s,
                        %s, %s,
                        %s, %s, %s, NULL, now()
                    )
                    """,
                    (
                        IDCLIENTE,
                        idfactura,
                        fecha,
                        vencimiento,
                        cliente_nit,
                        cliente_nombre,
                        total,
                        saldo,
                        centro_nombre,
                    ),
                )

            if random.random() <= 0.10:
                valor_nc = money(total * Decimal(random.choice(["0.04", "0.06", "0.08"])))

                cur.execute(
                    """
                    INSERT INTO siigo_notas_credito (
                        idcliente, nota_id, fecha, cliente_nombre,
                        vendedor, estado, total, created_at,
                        uuid, motivo, observaciones, customer_id,
                        factura_afectada_id, metadata_json, factura_afectada_uuid
                    )
                    VALUES (
                        %s, %s, %s, %s,
                        %s, 'Aplicada', %s, now(),
                        %s, %s, %s, %s,
                        %s, %s, %s
                    )
                    """,
                    (
                        IDCLIENTE,
                        f"NC-9-{nota_seq}",
                        min(add_days(fecha, random.choice([4, 8, 12])), d(2026, 5, 31)),
                        cliente_nombre,
                        vendedor_nombre,
                        valor_nc,
                        str(uuid.uuid4()),
                        "Ajuste comercial demo",
                        "Nota crédito demo por ajuste comercial controlado.",
                        customer_ids[cliente_nombre]["uuid"],
                        idfactura,
                        Json({"demo": True, "factura_afectada": idfactura}),
                        str(uuid.uuid4()),
                    ),
                )

                nota_seq += 1

            facturas_creadas.append(
                {
                    "mes": mes,
                    "idfactura": idfactura,
                    "cliente": cliente_nombre,
                    "nit": cliente_nit,
                    "subtotal": subtotal,
                    "iva": iva,
                    "total": total,
                    "saldo": saldo,
                    "pagos_total": pagos_total,
                }
            )

            factura_seq += 1

        gastos_mes = gastos_base_mes[mes]
        cantidad_compras = random.randint(12, 17)
        promedio_compra = Decimal(gastos_mes) / Decimal(cantidad_compras)

        conceptos_gasto = [
            ("513525", "Servicios de hosting y nube"),
            ("511095", "Consultoría tecnológica"),
            ("519595", "Producción de material comercial"),
            ("512010", "Arrendamiento oficina"),
            ("513525", "Servicios administrativos"),
            ("514525", "Mantenimiento de plataforma"),
            ("530505", "Gastos financieros"),
        ]

        for i in range(cantidad_compras):
            proveedor_nit, proveedor_nombre, proveedor_tipo, ciudad = random.choice(proveedores_demo)
            centro_id, centro_codigo, centro_nombre = random.choice(centros_costo_demo)
            cuenta_gasto, concepto = random.choice(conceptos_gasto)

            fecha = d(2026, mes, random.randint(2, 26))
            vencimiento = add_days(fecha, random.choice([15, 30, 45]))

            subtotal = money(promedio_compra * Decimal(str(random.uniform(0.60, 1.40))))
            iva = money(subtotal * Decimal("0.19"))
            total = money(subtotal + iva)

            estado_random = random.random()

            if estado_random <= 0.62:
                estado = "pagada"
                pago_valor = total
                saldo = money(0)
            elif estado_random <= 0.82:
                estado = "parcial"
                pago_valor = money(total * Decimal(random.choice(["0.40", "0.55", "0.70"])))
                saldo = money(total - pago_valor)
            else:
                estado = "pendiente"
                pago_valor = money(0)
                saldo = total

            if proveedor_tipo == "NIT":
                idcompra = f"FC-9-{compra_seq}"
                factura_proveedor = f"FC-{compra_seq}"
            else:
                idcompra = f"DS-9-{compra_seq}"
                factura_proveedor = f"DS-{compra_seq}"

            cur.execute(
                """
                INSERT INTO siigo_compras (
                    idcliente, idcompra, fecha, vencimiento,
                    proveedor_nombre, proveedor_identificacion,
                    estado, total, saldo, cost_center,
                    creado, created_at, factura_proveedor,
                    total_ajustes_debito, total_ajustado,
                    estado_ajuste, ajustes_count, ajustes_updated_at
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s,
                    %s, %s, %s, %s,
                    now(), now(), %s,
                    0, %s,
                    'sin_ajuste', 0, NULL
                )
                RETURNING id
                """,
                (
                    IDCLIENTE,
                    idcompra,
                    fecha,
                    vencimiento,
                    proveedor_nombre,
                    proveedor_nit,
                    estado,
                    total,
                    saldo,
                    centro_id,
                    factura_proveedor,
                    total,
                ),
            )

            compra_db_id = cur.fetchone()[0]

            cur.execute(
                """
                INSERT INTO siigo_compras_items (
                    compra_id, descripcion, cantidad,
                    precio, impuestos, codigo, idcliente
                )
                VALUES (
                    %s, %s, 1,
                    %s, %s, %s, %s
                )
                """,
                (
                    compra_db_id,
                    concepto,
                    subtotal,
                    iva,
                    cuenta_gasto,
                    IDCLIENTE,
                ),
            )

            if pago_valor > 0:
                fecha_pago = min(add_days(fecha, random.choice([5, 10, 18, 32])), d(2026, 5, 31))

                cur.execute(
                    """
                    INSERT INTO siigo_pagos_proveedores (
                        idcliente, idpago, fecha,
                        proveedor_nombre, metodo_pago, valor,
                        factura_aplicada, created_at,
                        factura_pagada, proveedor_identificacion
                    )
                    VALUES (
                        %s, %s, %s,
                        %s, %s, %s,
                        %s, now(),
                        %s, %s
                    )
                    """,
                    (
                        IDCLIENTE,
                        f"PP-9-{pago_proveedor_seq}",
                        fecha_pago,
                        proveedor_nombre,
                        random.choice(["TRANSF", "ACH", "CONSIG"]),
                        pago_valor,
                        idcompra,
                        factura_proveedor,
                        proveedor_nit,
                    ),
                )
                pago_proveedor_seq += 1

            compras_creadas.append(
                {
                    "mes": mes,
                    "idcompra": idcompra,
                    "proveedor": proveedor_nombre,
                    "nit": proveedor_nit,
                    "cuenta_gasto": cuenta_gasto,
                    "subtotal": subtotal,
                    "iva": iva,
                    "total": total,
                    "saldo": saldo,
                    "pago_valor": pago_valor,
                }
            )

            compra_seq += 1

    return facturas_creadas, compras_creadas


def insertar_nomina(cur):
    print("Insertando nómina demo...")

    resumen_nomina = {}

    for mes in range(1, 6):
        total_ingresos_mes = money(0)
        neto_mes = money(0)

        for nombre, identificacion, contrato, sueldo_valor in empleados_demo:
            periodo = fin_mes(2026, mes)

            sueldo = money(sueldo_valor)
            aux_transporte = money(0)
            auxilio_extralegal = money(random.choice([0, 0, 250000, 400000]))
            total_ingresos = money(sueldo + aux_transporte + auxilio_extralegal)

            salud = money(sueldo * Decimal("0.04"))
            pension = money(sueldo * Decimal("0.04"))
            solidaridad = money(sueldo * Decimal("0.01")) if sueldo >= 6000000 else money(0)
            retefuente = money(random.choice([0, 0, 180000, 320000])) if sueldo >= 6000000 else money(0)
            prestamos = money(random.choice([0, 0, 150000]))

            total_deducciones = money(salud + pension + solidaridad + retefuente + prestamos)
            neto_pagar = money(total_ingresos - total_deducciones)

            cur.execute(
                """
                INSERT INTO siigo_nomina (
                    idcliente, periodo, nombre, identificacion,
                    no_contrato, sueldo, aux_transporte,
                    auxilio_extralegal, total_ingresos,
                    fondo_salud, fondo_pension, fondo_solidaridad,
                    retefuente, prestamos, total_deducciones,
                    neto_pagar, creado, prima, intereses_cesantias
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, now(), 0, 0
                )
                """,
                (
                    IDCLIENTE,
                    periodo,
                    nombre,
                    identificacion,
                    contrato,
                    sueldo,
                    aux_transporte,
                    auxilio_extralegal,
                    total_ingresos,
                    salud,
                    pension,
                    solidaridad,
                    retefuente,
                    prestamos,
                    total_deducciones,
                    neto_pagar,
                ),
            )

            total_ingresos_mes += total_ingresos
            neto_mes += neto_pagar

        resumen_nomina[mes] = {
            "total_ingresos": total_ingresos_mes,
            "neto_pagar": neto_mes,
        }

    return resumen_nomina


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
        )
        VALUES (
            %s, %s,
            %s, %s,
            %s, %s,
            %s, %s,
            %s, %s, %s, %s,
            now(), 'seed_demo_comercial_2026.py',
            %s, %s
        )
        """,
        (
            IDCLIENTE,
            fecha_contable,
            tipo,
            numero,
            cuenta_codigo,
            cuenta["nombre"],
            tercero_nit,
            tercero_nombre,
            detalle,
            money(debito),
            money(credito),
            money(base),
            fecha_contable.year,
            fecha_contable.month,
        ),
    )


def insertar_contabilidad(cur, facturas, compras, resumen_nomina):
    print("Insertando auxiliar contable, saldos a corte y balance de prueba...")

    saldos = {codigo: money(0) for codigo in cuentas.keys()}

    # Capital inicial y activos iniciales
    fecha_inicial = d(2026, 1, 1)

    insertar_auxiliar(cur, fecha_inicial, "AP", "AP-DEMO-2026", "111005", None, None, "Aporte inicial en bancos", debito=180000000)
    insertar_auxiliar(cur, fecha_inicial, "AP", "AP-DEMO-2026", "152405", None, None, "Equipos de oficina iniciales", debito=35000000)
    insertar_auxiliar(cur, fecha_inicial, "AP", "AP-DEMO-2026", "310505", None, None, "Capital social inicial", credito=215000000)

    saldos["111005"] += money(180000000)
    saldos["152405"] += money(35000000)
    saldos["310505"] += money(215000000)

    for mes in range(1, 6):
        fecha_mes = fin_mes(2026, mes)

        facturas_mes = [f for f in facturas if f["mes"] == mes]
        compras_mes = [c for c in compras if c["mes"] == mes]

        ventas_subtotal = sum((f["subtotal"] for f in facturas_mes), money(0))
        ventas_iva = sum((f["iva"] for f in facturas_mes), money(0))
        ventas_total = sum((f["total"] for f in facturas_mes), money(0))
        ventas_saldo = sum((f["saldo"] for f in facturas_mes), money(0))
        ventas_pagadas = sum((f["pagos_total"] for f in facturas_mes), money(0))

        retencion_favor = money(ventas_subtotal * Decimal("0.025"))
        reteica_favor = money(ventas_subtotal * Decimal("0.00966"))
        reteiva_favor = money(ventas_iva * Decimal("0.15"))
        valor_clientes_neto = money(ventas_total - retencion_favor - reteica_favor - reteiva_favor)

        # Causación ventas mensual
        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-MES-{mes:02d}", "130505", None, "Clientes demo", "Causación ventas demo del mes", debito=valor_clientes_neto, base=ventas_subtotal)
        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-MES-{mes:02d}", "135515", None, "Clientes demo", "Retención en la fuente a favor por ventas", debito=retencion_favor, base=ventas_subtotal)
        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-MES-{mes:02d}", "135518", None, "Clientes demo", "ReteICA a favor por ventas", debito=reteica_favor, base=ventas_subtotal)
        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-MES-{mes:02d}", "13551701", None, "Clientes demo", "ReteIVA a favor por ventas", debito=reteiva_favor, base=ventas_subtotal)
        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-MES-{mes:02d}", "413595", None, "Clientes demo", "Ingresos por servicios tecnológicos", credito=ventas_subtotal, base=ventas_subtotal)
        insertar_auxiliar(cur, fecha_mes, "FV", f"FV-DEMO-MES-{mes:02d}", "24080601", None, "Clientes demo", "IVA generado servicios 19%", credito=ventas_iva, base=ventas_subtotal)

        saldos["130505"] += valor_clientes_neto
        saldos["135515"] += retencion_favor
        saldos["135518"] += reteica_favor
        saldos["13551701"] += reteiva_favor
        saldos["413595"] += ventas_subtotal
        saldos["24080601"] += ventas_iva

        # Recaudo de cartera
        insertar_auxiliar(cur, fecha_mes, "RC", f"RC-DEMO-MES-{mes:02d}", "111005", None, "Clientes demo", "Recaudos recibidos de clientes", debito=ventas_pagadas)
        insertar_auxiliar(cur, fecha_mes, "RC", f"RC-DEMO-MES-{mes:02d}", "130505", None, "Clientes demo", "Abono de cartera por recaudos", credito=ventas_pagadas)

        saldos["111005"] += ventas_pagadas
        saldos["130505"] -= ventas_pagadas

        # Compras/gastos
        compras_subtotal_total = sum((c["subtotal"] for c in compras_mes), money(0))
        compras_iva = sum((c["iva"] for c in compras_mes), money(0))
        compras_total = sum((c["total"] for c in compras_mes), money(0))
        compras_pagadas = sum((c["pago_valor"] for c in compras_mes), money(0))

        retencion_pagar = money(compras_subtotal_total * Decimal("0.04"))
        reteica_pagar = money(compras_subtotal_total * Decimal("0.00966"))
        proveedor_neto = money(compras_total - retencion_pagar - reteica_pagar)

        gastos_por_cuenta = {}
        for c in compras_mes:
            gastos_por_cuenta[c["cuenta_gasto"]] = gastos_por_cuenta.get(c["cuenta_gasto"], money(0)) + c["subtotal"]

        for cuenta_gasto, valor in gastos_por_cuenta.items():
            insertar_auxiliar(cur, fecha_mes, "CP", f"CP-DEMO-MES-{mes:02d}", cuenta_gasto, None, "Proveedores demo", f"Gasto demo cuenta {cuenta_gasto}", debito=valor, base=valor)
            saldos[cuenta_gasto] += valor

        insertar_auxiliar(cur, fecha_mes, "CP", f"CP-DEMO-MES-{mes:02d}", "24081501", None, "Proveedores demo", "Descontable por servicios 19%", debito=compras_iva, base=compras_subtotal_total)
        insertar_auxiliar(cur, fecha_mes, "CP", f"CP-DEMO-MES-{mes:02d}", "220505", None, "Proveedores demo", "Cuentas por pagar a proveedores", credito=proveedor_neto, base=compras_subtotal_total)
        insertar_auxiliar(cur, fecha_mes, "CP", f"CP-DEMO-MES-{mes:02d}", "236540", None, "Proveedores demo", "Retención en la fuente por pagar", credito=retencion_pagar, base=compras_subtotal_total)
        insertar_auxiliar(cur, fecha_mes, "CP", f"CP-DEMO-MES-{mes:02d}", "236805", None, "Proveedores demo", "ReteICA por pagar", credito=reteica_pagar, base=compras_subtotal_total)

        saldos["24081501"] += compras_iva
        saldos["220505"] += proveedor_neto
        saldos["236540"] += retencion_pagar
        saldos["236805"] += reteica_pagar

        # Pagos a proveedores
        insertar_auxiliar(cur, fecha_mes, "PP", f"PP-DEMO-MES-{mes:02d}", "220505", None, "Proveedores demo", "Pagos realizados a proveedores", debito=compras_pagadas)
        insertar_auxiliar(cur, fecha_mes, "PP", f"PP-DEMO-MES-{mes:02d}", "111005", None, "Proveedores demo", "Salida de bancos por pagos a proveedores", credito=compras_pagadas)

        saldos["220505"] -= compras_pagadas
        saldos["111005"] -= compras_pagadas

        # Nómina
        nomina_total = resumen_nomina[mes]["total_ingresos"]
        nomina_neto = resumen_nomina[mes]["neto_pagar"]

        insertar_auxiliar(cur, fecha_mes, "NM", f"NM-DEMO-MES-{mes:02d}", "510506", None, "Empleados demo", "Causación nómina mensual", debito=nomina_total, base=nomina_total)
        insertar_auxiliar(cur, fecha_mes, "NM", f"NM-DEMO-MES-{mes:02d}", "250505", None, "Empleados demo", "Nómina por pagar", credito=nomina_total)

        saldos["510506"] += nomina_total
        saldos["250505"] += nomina_total

        insertar_auxiliar(cur, fecha_mes, "PN", f"PN-DEMO-MES-{mes:02d}", "250505", None, "Empleados demo", "Pago de nómina mensual", debito=nomina_neto)
        insertar_auxiliar(cur, fecha_mes, "PN", f"PN-DEMO-MES-{mes:02d}", "111005", None, "Empleados demo", "Salida de bancos por pago de nómina", credito=nomina_neto)

        saldos["250505"] -= nomina_neto
        saldos["111005"] -= nomina_neto

        # Utilidad acumulada estimada para balance
        ingresos = saldos["413595"]
        gastos = (
            saldos["510506"]
            + saldos["511095"]
            + saldos["512010"]
            + saldos["513525"]
            + saldos["514525"]
            + saldos["519595"]
            + saldos["530505"]
        )
        utilidad = money(ingresos - gastos)
        saldos["360505"] = utilidad

        insertar_saldos_corte_y_balance(cur, fin_mes(2026, mes), saldos)


def insertar_saldos_corte_y_balance(cur, fecha_corte, saldos):
    for codigo, saldo in saldos.items():
        cuenta = cuentas[codigo]

        if saldo == 0:
            continue

        cuenta_padre = codigo[:4]

        # Clasificación compatible con auxiliar_saldos_corte real:
        # clase = primer dígito de la cuenta
        # grupo = primeros dos dígitos de la cuenta
        # seccion, grupo_balance y naturaleza según clase contable.
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
            )
            VALUES (
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                now(), 'SEED_DEMO'
            )
            """,
            (
                IDCLIENTE,
                fecha_corte,
                codigo,
                cuenta["nombre"],
                cuenta_padre,
                clase_calc,
                grupo_calc,
                seccion_calc,
                grupo_balance_calc,
                naturaleza_calc,
                saldo_final,
            ),
        )

        # Para balance_prueba se registran movimientos por naturaleza,
        # manteniendo saldo_final con signo.
        movimiento_debito = money(abs(saldo_final)) if naturaleza_calc == "DEBITO_MENOS_CREDITO" else money(0)
        movimiento_credito = money(abs(saldo_final)) if naturaleza_calc == "CREDITO_MENOS_DEBITO" else money(0)

        cur.execute(
            """
            INSERT INTO balance_prueba (
                idcliente, codigo_cuenta, nombre_cuenta,
                nivel, es_transaccional,
                saldo_inicial, movimiento_debito, movimiento_credito,
                saldo_final, periodo_anio, periodo_mes_inicio,
                periodo_mes_fin, fecha_carga
            )
            VALUES (
                %s, %s, %s,
                'auxiliar', true,
                0, %s, %s,
                %s, %s, 1,
                %s, now()
            )
            """,
            (
                IDCLIENTE,
                codigo,
                cuenta["nombre"],
                movimiento_debito,
                movimiento_credito,
                saldo_final,
                fecha_corte.year,
                fecha_corte.month,
            ),
        )


def validar(cur):
    print("\nResumen final:")

    consultas = [
        ("Clientes Siigo", "SELECT COUNT(*), 0, 0 FROM siigo_customers WHERE idcliente = 14"),
        ("Productos", "SELECT COUNT(*), 0, 0 FROM siigo_productos WHERE idcliente = 14"),
        ("Proveedores", "SELECT COUNT(*), 0, 0 FROM siigo_proveedores WHERE idcliente = 14"),
        ("Facturas", "SELECT COUNT(*), COALESCE(SUM(total),0), COALESCE(SUM(saldo),0) FROM siigo_facturas WHERE idcliente = 14"),
        ("Notas crédito", "SELECT COUNT(*), COALESCE(SUM(total),0), 0 FROM siigo_notas_credito WHERE idcliente = 14"),
        ("Pagos recibidos", "SELECT COUNT(*), COALESCE(SUM(valor),0), 0 FROM siigo_pagos_recibidos WHERE idcliente = 14"),
        ("CxC", "SELECT COUNT(*), COALESCE(SUM(valor),0), COALESCE(SUM(saldo),0) FROM siigo_cuentasporcobrar WHERE idcliente = 14"),
        ("Compras", "SELECT COUNT(*), COALESCE(SUM(total),0), COALESCE(SUM(saldo),0) FROM siigo_compras WHERE idcliente = 14"),
        ("Pagos proveedores", "SELECT COUNT(*), COALESCE(SUM(valor),0), 0 FROM siigo_pagos_proveedores WHERE idcliente = 14"),
        ("Nómina", "SELECT COUNT(*), COALESCE(SUM(neto_pagar),0), 0 FROM siigo_nomina WHERE idcliente = 14"),
        ("Auxiliar contable", "SELECT COUNT(*), COALESCE(SUM(debito),0), COALESCE(SUM(credito),0) FROM auxiliar_contable WHERE idcliente = 14"),
        ("Saldos corte", "SELECT COUNT(*), COALESCE(SUM(saldo),0), 0 FROM auxiliar_saldos_corte WHERE idcliente = 14"),
        ("Balance prueba", "SELECT COUNT(*), COALESCE(SUM(saldo_final),0), 0 FROM balance_prueba WHERE idcliente = 14"),
    ]

    for nombre, sql in consultas:
        cur.execute(sql)
        a, b, c = cur.fetchone()
        print(f"{nombre}: registros={a}, total_1={b}, total_2={c}")

    print("\nVentas por mes:")
    cur.execute(
        """
        SELECT 
            DATE_TRUNC('month', fecha)::date AS mes,
            COUNT(*) AS facturas,
            SUM(subtotal) AS subtotal,
            SUM(total) AS total,
            SUM(saldo) AS saldo
        FROM siigo_facturas
        WHERE idcliente = 14
        GROUP BY 1
        ORDER BY 1
        """
    )
    for row in cur.fetchall():
        print(row)

    print("\nCompras por mes:")
    cur.execute(
        """
        SELECT 
            DATE_TRUNC('month', fecha)::date AS mes,
            COUNT(*) AS compras,
            SUM(total) AS total,
            SUM(saldo) AS saldo
        FROM siigo_compras
        WHERE idcliente = 14
        GROUP BY 1
        ORDER BY 1
        """
    )
    for row in cur.fetchall():
        print(row)


def main():
    conn = psycopg2.connect(DATABASE_URL)

    try:
        with conn:
            with conn.cursor() as cur:
                limpiar_data_demo(cur)
                asegurar_configuraciones(cur)
                customer_ids, producto_ids = insertar_catalogos(cur)
                facturas, compras = insertar_operacion_siigo(cur, customer_ids, producto_ids)
                resumen_nomina = insertar_nomina(cur)
                insertar_contabilidad(cur, facturas, compras, resumen_nomina)
                validar(cur)

        print("\nCarga demo comercial 2026 finalizada correctamente.")

    except Exception as e:
        conn.rollback()
        print("\nERROR. Se hizo rollback. No quedó la carga parcial.")
        raise e

    finally:
        conn.close()


if __name__ == "__main__":
    main()
