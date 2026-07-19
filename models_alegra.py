"""
Modelos SQLAlchemy del conector Alegra, aislados de models.py (Siigo) por diseño
(ver InsightsFlow_Alegra_Plan_Maestro.md, seccion 1 - riesgo aceptado y mitigacion).

Comparten la misma instancia `db` que models.py para registrarse en el mismo
metadata/engine de Flask-SQLAlchemy. Convenciones seguidas: ver seccion 4.5 del
plan maestro (contraste hecho contra models.py real, 2026-07-08).
"""

from datetime import datetime

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import JSONB

from models import db


# ---------------------------------------------------------------------------
# 4.1 Config / control
# ---------------------------------------------------------------------------

class FuenteDatosCliente(db.Model):
    __tablename__ = "fuente_datos_cliente"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(
        db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"),
        unique=True, nullable=False,
    )
    proveedor = db.Column(db.String(20), nullable=False)  # 'siigo' | 'alegra'
    activo = db.Column(db.Boolean, default=True)
    fecha_conexion = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "proveedor": self.proveedor,
            "activo": self.activo,
            "fecha_conexion": self.fecha_conexion.isoformat() if self.fecha_conexion else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AlegraCredencial(db.Model):
    __tablename__ = "alegra_credenciales"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(
        db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"),
        unique=True, nullable=False,
    )
    email = db.Column(db.Text, nullable=False)          # usuario Basic Auth
    token = db.Column(db.LargeBinary, nullable=False)    # cifrado (Fernet, igual que SiigoCredencial)
    updated_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AlegraSyncConfig(db.Model):
    __tablename__ = "alegra_sync_config"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    hora_ejecucion = db.Column(db.Time, nullable=False)
    frecuencia_dias = db.Column(db.Integer, default=1)
    activo = db.Column(db.Boolean, default=True)
    ultimo_ejecutado = db.Column(db.DateTime(timezone=True))
    # Distingue "ultima vez que corrio, manual o cron" (ultimo_ejecutado) de
    # "ultima vez que corrio EL CRON especificamente" (este campo) - necesario
    # para que cron_sync.py sepa si ya cumplio su ejecucion automatica de hoy
    # sin que un clic manual del usuario la tape. Mismo patron que
    # SiigoSyncConfig.ultimo_auto_ejecutado.
    ultimo_auto_ejecutado = db.Column(db.DateTime(timezone=True))
    resultado_ultima_sync = db.Column(db.Text)
    detalle_ultima_sync = db.Column(db.Text)
    sync_fecha_desde = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "hora_ejecucion": self.hora_ejecucion.strftime("%H:%M") if self.hora_ejecucion else None,
            "frecuencia_dias": self.frecuencia_dias,
            "activo": self.activo,
            "ultimo_ejecutado": self.ultimo_ejecutado.isoformat() if self.ultimo_ejecutado else None,
            "ultimo_auto_ejecutado": self.ultimo_auto_ejecutado.isoformat() if self.ultimo_auto_ejecutado else None,
            "resultado_ultima_sync": self.resultado_ultima_sync,
            "detalle_ultima_sync": self.detalle_ultima_sync,
            "sync_fecha_desde": self.sync_fecha_desde.isoformat() if self.sync_fecha_desde else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AlegraSyncLog(db.Model):
    __tablename__ = "alegra_sync_logs"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    fecha_programada = db.Column(db.DateTime(timezone=True), nullable=False)
    ejecutado_en = db.Column(db.DateTime(timezone=True))
    resultado = db.Column(db.Text)
    detalle = db.Column(db.Text)
    origen = db.Column(db.String(20))
    total_pasos = db.Column(db.Integer, default=0)
    pasos_ok = db.Column(db.Integer, default=0)
    pasos_error = db.Column(db.Integer, default=0)
    endpoint_fallido = db.Column(db.Text)
    creado_en = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "fecha_programada": self.fecha_programada.isoformat() if self.fecha_programada else None,
            "ejecutado_en": self.ejecutado_en.isoformat() if self.ejecutado_en else None,
            "resultado": self.resultado,
            "detalle": self.detalle,
            "origen": self.origen,
            "total_pasos": self.total_pasos or 0,
            "pasos_ok": self.pasos_ok or 0,
            "pasos_error": self.pasos_error or 0,
            "endpoint_fallido": self.endpoint_fallido,
            "creado_en": self.creado_en.isoformat() if self.creado_en else None,
        }


class AlegraSyncMetric(db.Model):
    __tablename__ = "alegra_sync_metrics"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    endpoint = db.Column(db.Text, nullable=False)
    duracion_segundos = db.Column(db.Numeric(8, 2))
    status_code = db.Column(db.Integer)
    resultado = db.Column(db.Text)
    detalle_resumen = db.Column(db.Text)
    ejecutado_en = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "endpoint": self.endpoint,
            "duracion_segundos": float(self.duracion_segundos or 0),
            "status_code": self.status_code,
            "resultado": self.resultado,
            "detalle_resumen": (self.detalle_resumen[:300] + "...") if self.detalle_resumen and len(self.detalle_resumen) > 300 else self.detalle_resumen,
            "ejecutado_en": self.ejecutado_en.isoformat() if self.ejecutado_en else None,
        }


# ---------------------------------------------------------------------------
# 4.2 Bloque contable
# ---------------------------------------------------------------------------

class AlegraCuentaContable(db.Model):
    __tablename__ = "alegra_cuentas_contables"

    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    alegra_id = db.Column(db.String(50), nullable=False)  # id interno estable de Alegra (/categories)

    code = db.Column(db.String(50))            # nullable: puede faltar (NIIF) o venir ""
    name = db.Column(db.String(255))
    type = db.Column(db.String(30))             # asset/liability/equity/income/expense/cost/...
    nature = db.Column(db.String(10))            # debit/credit
    use = db.Column(db.String(20))               # accumulative | movement
    category_rule_key = db.Column(db.String(50))  # ej. SALES, BANK_ACCOUNTS, IVA_TO_PAY_COL
    parent_id = db.Column(db.String(50))          # id natural del padre, sin FK (arbol via /categories)
    fecha_sincronizacion = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.PrimaryKeyConstraint("idcliente", "alegra_id"),
    )

    def as_dict(self):
        return {
            "idcliente": self.idcliente,
            "alegra_id": self.alegra_id,
            "code": self.code,
            "name": self.name,
            "type": self.type,
            "nature": self.nature,
            "use": self.use,
            "category_rule_key": self.category_rule_key,
            "parent_id": self.parent_id,
            "fecha_sincronizacion": self.fecha_sincronizacion.isoformat() if self.fecha_sincronizacion else None,
        }


class AlegraCoberturaContable(db.Model):
    """Snapshot de lo que /alegra/cargar_libro_diario descarta por no poder
    resolver un codigo PUC (ni directo del Excel ni por fallback de nombre
    contra AlegraCuentaContable.code). Se captura EN EL MOMENTO de la carga
    porque las filas descartadas nunca llegan a auxiliar_contable - despues
    de ese punto la informacion ya no existe en ningun lado. Reemplazo por
    rango de fechas igual que auxiliar_contable (ver cargar_libro_diario)."""
    __tablename__ = "alegra_cobertura_contable"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    fecha = db.Column(db.Date, nullable=False)
    cuenta_nombre = db.Column(db.String(255), nullable=False)
    tipo_cuenta = db.Column(db.String(30))  # AlegraCuentaContable.type en el momento de la carga; None si no hay match en el catalogo
    en_catalogo = db.Column(db.Boolean, default=False)  # True: la cuenta existe en alegra_cuentas_contables (falta codigo). False: el nombre no existe como cuenta real del cliente en Alegra (ej. subrenglones de nomina)
    debito = db.Column(db.Numeric(18, 2), default=0)
    credito = db.Column(db.Numeric(18, 2), default=0)
    n_filas = db.Column(db.Integer, default=0)
    fecha_carga = db.Column(db.DateTime, default=datetime.utcnow)


class AlegraMovimiento(db.Model):
    __tablename__ = "alegra_movimientos"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)

    journal_id = db.Column(db.String(50), nullable=False)
    entry_id = db.Column(db.String(50), nullable=False)  # linea dentro del comprobante

    fecha = db.Column(db.Date, nullable=False)
    alegra_account_id = db.Column(db.String(50), nullable=False)  # ref blanda a alegra_cuentas_contables.alegra_id
    tercero_id = db.Column(db.String(50))                          # ref blanda a alegra_terceros.alegra_id
    debito = db.Column(db.Numeric(18, 2), default=0)
    credito = db.Column(db.Numeric(18, 2), default=0)
    descripcion = db.Column(db.Text)

    associated_document_type = db.Column(db.String(30))  # ej. 'bill', 'invoice'
    associated_document_id = db.Column(db.String(50))

    fecha_sincronizacion = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("idcliente", "journal_id", "entry_id", name="uq_alegra_movimiento_entry"),
        db.Index("ix_alegra_movimientos_cuenta", "idcliente", "alegra_account_id", "fecha"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "journal_id": self.journal_id,
            "entry_id": self.entry_id,
            "fecha": self.fecha.isoformat() if self.fecha else None,
            "alegra_account_id": self.alegra_account_id,
            "tercero_id": self.tercero_id,
            "debito": float(self.debito or 0),
            "credito": float(self.credito or 0),
            "descripcion": self.descripcion,
            "associated_document_type": self.associated_document_type,
            "associated_document_id": self.associated_document_id,
        }


class AlegraSaldoCuenta(db.Model):
    """Saldo cacheado por cuenta/periodo. Calculado por InsightsFlow, no viene de la API
    (confirmado 2026-07-07: /journals/entries/graph no desglosa por cuenta)."""
    __tablename__ = "alegra_saldos_cuenta"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    alegra_account_id = db.Column(db.String(50), nullable=False)
    periodo = db.Column(db.Date, nullable=False)  # primer dia del periodo (mes) representado

    saldo_inicial = db.Column(db.Numeric(18, 2), default=0)
    debitos = db.Column(db.Numeric(18, 2), default=0)
    creditos = db.Column(db.Numeric(18, 2), default=0)
    saldo_final = db.Column(db.Numeric(18, 2), default=0)

    fecha_calculo = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("idcliente", "alegra_account_id", "periodo", name="uq_alegra_saldo_cuenta_periodo"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "alegra_account_id": self.alegra_account_id,
            "periodo": self.periodo.isoformat() if self.periodo else None,
            "saldo_inicial": float(self.saldo_inicial or 0),
            "debitos": float(self.debitos or 0),
            "creditos": float(self.creditos or 0),
            "saldo_final": float(self.saldo_final or 0),
        }


class AlegraSaldoInicial(db.Model):
    """Saldo de apertura por cuenta, cargado desde el 'Estado de situación
    financiera' nativo de Alegra al corte anterior al primer mes con Libro
    Diario cargado (ej. 31-dic del año anterior). Necesario porque
    regenerar_snapshot_saldos_corte (balance.py) acumula auxiliar_contable
    desde cero sin ningun concepto de apertura - confirmado con datos reales
    de Maslux LED e Importadora NGC (2026-07-15/18) que esto rompe CxC/CxP/
    patrimonio/retenciones por igual (no solo cuentas puntuales) para
    cualquier cliente Alegra migrado a mitad de año fiscal. Ver
    Docs_integracion/alegra_crear_tabla_saldos_iniciales.sql."""
    __tablename__ = "alegra_saldos_iniciales"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    fecha_corte_inicial = db.Column(db.Date, nullable=False)

    cuenta_codigo = db.Column(db.String(30), nullable=False)
    cuenta_nombre = db.Column(db.String(255))
    saldo = db.Column(db.Numeric(18, 2), nullable=False)

    archivo_origen = db.Column(db.String(255))
    fecha_carga = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint(
            "idcliente", "fecha_corte_inicial", "cuenta_codigo",
            name="uq_alegra_saldo_inicial_corte_cuenta",
        ),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "fecha_corte_inicial": self.fecha_corte_inicial.isoformat() if self.fecha_corte_inicial else None,
            "cuenta_codigo": self.cuenta_codigo,
            "cuenta_nombre": self.cuenta_nombre,
            "saldo": float(self.saldo or 0),
        }


# ---------------------------------------------------------------------------
# 4.3 Bloque operativo
# ---------------------------------------------------------------------------

class AlegraTercero(db.Model):
    __tablename__ = "alegra_terceros"

    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    alegra_id = db.Column(db.String(50), nullable=False)

    nombre = db.Column(db.String(255))
    identificacion = db.Column(db.String(50))
    tipo = db.Column(db.String(20))  # 'cliente' | 'proveedor' | 'ambos' | 'otro' (derivado de `type`, [] posible)
    regimen = db.Column(db.String(30))  # COMMON_REGIME | SIMPLIFIED_REGIME
    responsabilidades_fiscales = db.Column(JSONB)
    uuid_alegra = db.Column(db.String(50))
    fecha_sincronizacion = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.PrimaryKeyConstraint("idcliente", "alegra_id"),
    )

    def as_dict(self):
        return {
            "idcliente": self.idcliente,
            "alegra_id": self.alegra_id,
            "nombre": self.nombre,
            "identificacion": self.identificacion,
            "tipo": self.tipo,
            "regimen": self.regimen,
            "responsabilidades_fiscales": self.responsabilidades_fiscales,
            "uuid_alegra": self.uuid_alegra,
        }


class AlegraFactura(db.Model):
    __tablename__ = "alegra_facturas"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    alegra_id = db.Column(db.String(50), nullable=False)

    fecha = db.Column(db.Date)
    vencimiento = db.Column(db.Date)

    tercero_id = db.Column(db.String(50))       # ref blanda a alegra_terceros.alegra_id
    tercero_nombre = db.Column(db.String(255))
    vendedor_id = db.Column(db.String(50))       # ref blanda; puede venir null a nivel de factura
    centro_costo_id = db.Column(db.String(50))

    subtotal = db.Column(db.Numeric(18, 2))          # confirmado con dato real 2026-07-09: campo 'subtotal' de cabecera
    impuestos_total = db.Column(db.Numeric(18, 2))    # confirmado con dato real 2026-07-09: campo 'tax' de cabecera (numerico, no array)
    total = db.Column(db.Numeric(18, 2))
    balance = db.Column(db.Numeric(18, 2))        # saldo pendiente, viene directo de la API
    total_paid = db.Column(db.Numeric(18, 2))
    estado = db.Column(db.String(30))
    moneda = db.Column(db.String(10))

    retenciones = db.Column(JSONB)   # [] en la mayoria de casos vistos; ver alegra_compra_retenciones para compras
    payments = db.Column(JSONB)       # historial de pagos embebido
    stamp = db.Column(JSONB)          # CUFE / estado DIAN, null si no factura electronicamente

    metadata_created = db.Column(db.DateTime)
    metadata_updated = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    items = db.relationship(
        "AlegraFacturaItem",
        backref="factura",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    __table_args__ = (
        db.UniqueConstraint("idcliente", "alegra_id", name="uq_alegra_factura_idcliente_alegraid"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "alegra_id": self.alegra_id,
            "fecha": self.fecha.isoformat() if self.fecha else None,
            "vencimiento": self.vencimiento.isoformat() if self.vencimiento else None,
            "tercero_id": self.tercero_id,
            "tercero_nombre": self.tercero_nombre,
            "vendedor_id": self.vendedor_id,
            "centro_costo_id": self.centro_costo_id,
            "subtotal": float(self.subtotal or 0),
            "impuestos_total": float(self.impuestos_total or 0),
            "total": float(self.total or 0),
            "balance": float(self.balance or 0),
            "total_paid": float(self.total_paid or 0),
            "estado": self.estado,
            "moneda": self.moneda,
            "retenciones": self.retenciones,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AlegraFacturaItem(db.Model):
    __tablename__ = "alegra_factura_items"

    id = db.Column(db.Integer, primary_key=True)
    factura_id = db.Column(db.Integer, db.ForeignKey("alegra_facturas.id", ondelete="CASCADE"), nullable=False)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)

    producto_id = db.Column(db.String(50))  # ref blanda a alegra_productos.alegra_id
    descripcion = db.Column(db.String(2000))
    cantidad = db.Column(db.Numeric(18, 4))
    precio = db.Column(db.Numeric(18, 2))
    descuento_valor = db.Column(db.Numeric(18, 2))
    total_item = db.Column(db.Numeric(18, 2))
    tax = db.Column(JSONB)  # array rico con categoryFavorable/categoryToBePaid/etc.

    def as_dict(self):
        return {
            "id": self.id,
            "factura_id": self.factura_id,
            "idcliente": self.idcliente,
            "producto_id": self.producto_id,
            "descripcion": self.descripcion,
            "cantidad": float(self.cantidad or 0),
            "precio": float(self.precio or 0),
            "descuento_valor": float(self.descuento_valor or 0),
            "total_item": float(self.total_item or 0),
            "tax": self.tax,
        }


class AlegraNotaCredito(db.Model):
    __tablename__ = "alegra_notas_credito"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    alegra_id = db.Column(db.String(50), nullable=False)

    fecha = db.Column(db.Date)
    subtotal = db.Column(db.Numeric(18, 2))          # confirmado con dato real 2026-07-10: 'subtotal' de cabecera, mismo shape que alegra_facturas
    impuestos_total = db.Column(db.Numeric(18, 2))    # confirmado con dato real 2026-07-10: campo 'tax' de cabecera (numerico, no array)
    total = db.Column(db.Numeric(18, 2))
    balance = db.Column(db.Numeric(18, 2))
    total_applied = db.Column(db.Numeric(18, 2))
    cliente_id = db.Column(db.String(50))
    estado = db.Column(db.String(30))
    stamp = db.Column(JSONB)          # CUFE / estado DIAN, mismo shape que alegra_facturas.stamp - null si no es electronica
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    facturas_afectadas = db.relationship(
        "AlegraNotaCreditoFactura",
        backref="nota_credito",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    __table_args__ = (
        db.UniqueConstraint("idcliente", "alegra_id", name="uq_alegra_nc_idcliente_alegraid"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "alegra_id": self.alegra_id,
            "fecha": self.fecha.isoformat() if self.fecha else None,
            "subtotal": float(self.subtotal or 0),
            "impuestos_total": float(self.impuestos_total or 0),
            "total": float(self.total or 0),
            "balance": float(self.balance or 0),
            "total_applied": float(self.total_applied or 0),
            "cliente_id": self.cliente_id,
            "estado": self.estado,
        }


class AlegraNotaCreditoFactura(db.Model):
    """Puente N:N confirmado con dato real (2026-07-07): `invoices` en la nota credito es
    un arreglo, una nota puede afectar varias facturas."""
    __tablename__ = "alegra_nota_credito_facturas"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    nota_credito_id = db.Column(db.Integer, db.ForeignKey("alegra_notas_credito.id", ondelete="CASCADE"), nullable=False)
    factura_alegra_id = db.Column(db.String(50), nullable=False)  # ref blanda a alegra_facturas.alegra_id
    monto_aplicado = db.Column(db.Numeric(18, 2))

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "nota_credito_id": self.nota_credito_id,
            "factura_alegra_id": self.factura_alegra_id,
            "monto_aplicado": float(self.monto_aplicado or 0),
        }


class AlegraCompra(db.Model):
    __tablename__ = "alegra_compras"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    alegra_id = db.Column(db.String(50), nullable=False)

    fecha = db.Column(db.Date)
    vencimiento = db.Column(db.Date)

    proveedor_id = db.Column(db.String(50))
    proveedor_nombre = db.Column(db.String(255))
    centro_costo_id = db.Column(db.String(50))

    # numberTemplate.fullNumber de /bills - confirmado con dato real 2026-07-10:
    # es el numero/referencia de la factura del proveedor (formato libre, propio
    # de cada proveedor, ej. "TC-455283", "EPU-395762"), equivalente a
    # SiigoCompra.factura_proveedor - no el id interno de Alegra (alegra_id).
    factura_proveedor = db.Column(db.String(100))

    total = db.Column(db.Numeric(18, 2))
    balance = db.Column(db.Numeric(18, 2))
    total_paid = db.Column(db.Numeric(18, 2))
    estado = db.Column(db.String(30))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    items = db.relationship(
        "AlegraCompraItem",
        backref="compra",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    retenciones = db.relationship(
        "AlegraCompraRetencion",
        backref="compra",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    __table_args__ = (
        db.UniqueConstraint("idcliente", "alegra_id", name="uq_alegra_compra_idcliente_alegraid"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "alegra_id": self.alegra_id,
            "fecha": self.fecha.isoformat() if self.fecha else None,
            "vencimiento": self.vencimiento.isoformat() if self.vencimiento else None,
            "proveedor_id": self.proveedor_id,
            "proveedor_nombre": self.proveedor_nombre,
            "centro_costo_id": self.centro_costo_id,
            "factura_proveedor": self.factura_proveedor,
            "total": float(self.total or 0),
            "balance": float(self.balance or 0),
            "total_paid": float(self.total_paid or 0),
            "estado": self.estado,
        }


class AlegraCompraItem(db.Model):
    """CONFIRMADO 2026-07-07: `purchases` viene O como items[] (compra de producto/inventario)
    O como categories[] (gasto/servicio directo a cuenta contable) - mutuamente excluyentes,
    por eso ambos FKs (blandos) son nullable."""
    __tablename__ = "alegra_compra_items"

    id = db.Column(db.Integer, primary_key=True)
    compra_id = db.Column(db.Integer, db.ForeignKey("alegra_compras.id", ondelete="CASCADE"), nullable=False)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)

    tipo = db.Column(db.String(20), nullable=False)  # 'item' | 'categoria'
    producto_id = db.Column(db.String(50))            # poblado si tipo='item'
    cuenta_contable_id = db.Column(db.String(50))       # poblado si tipo='categoria'

    descripcion = db.Column(db.String(2000))
    cantidad = db.Column(db.Numeric(18, 4))
    precio = db.Column(db.Numeric(18, 2))
    subtotal = db.Column(db.Numeric(18, 2))
    total = db.Column(db.Numeric(18, 2))
    tax = db.Column(JSONB)  # array rico, mismo shape que AlegraFacturaItem.tax - confirmado
    # con dato real 2026-07-10 vía API directa en categories[] Y items[] de /bills
    # (puede venir null si la línea no tiene impuesto, ej. bienes exentos/importados)

    def as_dict(self):
        return {
            "id": self.id,
            "compra_id": self.compra_id,
            "idcliente": self.idcliente,
            "tipo": self.tipo,
            "producto_id": self.producto_id,
            "cuenta_contable_id": self.cuenta_contable_id,
            "descripcion": self.descripcion,
            "cantidad": float(self.cantidad or 0),
            "precio": float(self.precio or 0),
            "subtotal": float(self.subtotal or 0),
            "total": float(self.total or 0),
            "tax": self.tax,
        }


class AlegraCompraRetencion(db.Model):
    """Shape real confirmado con dato real (2026-07-07, proveedor Transporte Porto Romero) -
    mas rico que la documentacion publica: incluye calculatedBy/exchangeRate/isAssumed.
    Una compra puede tener varias retenciones simultaneas (ej. RTEICA + Transporte de carga)."""
    __tablename__ = "alegra_compra_retenciones"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    compra_id = db.Column(db.Integer, db.ForeignKey("alegra_compras.id", ondelete="CASCADE"), nullable=False)
    retention_id = db.Column(db.String(50))  # ref blanda a alegra_retenciones_catalogo.alegra_id

    name = db.Column(db.String(255))
    percentage = db.Column(db.Numeric(9, 4))
    amount = db.Column(db.Numeric(18, 2))
    calculated_by = db.Column(db.String(20))    # 'percentage' (unico valor visto; 'value' no confirmado)
    exchange_rate = db.Column(db.Numeric(18, 4))  # null salvo compras multi-moneda
    is_assumed = db.Column(db.Boolean, default=False)  # 'retencion asumida' (comprador la asume sin descontarla)

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "compra_id": self.compra_id,
            "retention_id": self.retention_id,
            "name": self.name,
            "percentage": float(self.percentage or 0),
            "amount": float(self.amount or 0),
            "calculated_by": self.calculated_by,
            "exchange_rate": float(self.exchange_rate) if self.exchange_rate is not None else None,
            "is_assumed": self.is_assumed,
        }


class AlegraPago(db.Model):
    """Unifica lo que en Siigo es solo SiigoPagoProveedor: Alegra expone tambien pagos
    recibidos de clientes (tipo='in') ademas de pagos a proveedores (tipo='out')."""
    __tablename__ = "alegra_pagos"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    alegra_id = db.Column(db.String(50), nullable=False)

    tipo = db.Column(db.String(10), nullable=False)  # 'in' | 'out'
    fecha = db.Column(db.Date)
    valor = db.Column(db.Numeric(18, 2))
    metodo_pago = db.Column(db.String(100))
    banco_id = db.Column(db.String(50))
    tercero_id = db.Column(db.String(50))

    categoria_contable_id = db.Column(db.String(50))  # poblado solo si el pago va directo a una cuenta (sin documentos)
    estado = db.Column(db.String(20))                    # incluye 'void' (anulado) - filtrar en reportes

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    documentos_aplicados = db.relationship(
        "AlegraPagoFactura",
        backref="pago",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    __table_args__ = (
        db.UniqueConstraint("idcliente", "alegra_id", "tipo", name="uq_alegra_pago_idcliente_alegraid_tipo"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "alegra_id": self.alegra_id,
            "tipo": self.tipo,
            "fecha": self.fecha.isoformat() if self.fecha else None,
            "valor": float(self.valor or 0),
            "metodo_pago": self.metodo_pago,
            "banco_id": self.banco_id,
            "tercero_id": self.tercero_id,
            "categoria_contable_id": self.categoria_contable_id,
            "estado": self.estado,
        }


class AlegraPagoFactura(db.Model):
    """Puente para el caso (a) de /payments: pago aplicado contra documentos (facturas de
    venta si tipo='in', facturas de proveedor/bills si tipo='out') - CONFIRMADO 2026-07-07
    que un pago puede cubrir varios documentos a la vez. El caso (b) (pago directo a cuenta
    contable) no usa esta tabla, solo AlegraPago.categoria_contable_id."""
    __tablename__ = "alegra_pago_facturas"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    pago_id = db.Column(db.Integer, db.ForeignKey("alegra_pagos.id", ondelete="CASCADE"), nullable=False)

    documento_tipo = db.Column(db.String(20), nullable=False)  # 'factura' | 'compra'
    documento_alegra_id = db.Column(db.String(50), nullable=False)
    monto_aplicado = db.Column(db.Numeric(18, 2))

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "pago_id": self.pago_id,
            "documento_tipo": self.documento_tipo,
            "documento_alegra_id": self.documento_alegra_id,
            "monto_aplicado": float(self.monto_aplicado or 0),
        }


class AlegraProducto(db.Model):
    __tablename__ = "alegra_productos"

    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    alegra_id = db.Column(db.String(50), nullable=False)

    code = db.Column(db.String(100))
    name = db.Column(db.String(255))
    type = db.Column(db.String(30))  # 'product' confirmado; 'service' u otros sin confirmar

    categoria_id = db.Column(db.String(50))         # ref blanda a /item-categories
    cuenta_inventario_id = db.Column(db.String(50))    # ref blanda; viene directo en accounting.inventory
    cuenta_costo_venta_id = db.Column(db.String(50))    # ref blanda; accounting.inventariablePurchase

    impuestos = db.Column(JSONB)
    precios = db.Column(JSONB)   # soporta multiples listas de precio (dato nuevo vs Siigo)
    bodegas = db.Column(JSONB)   # cantidades por bodega ya embebidas

    fecha_sincronizacion = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.PrimaryKeyConstraint("idcliente", "alegra_id"),
    )

    def as_dict(self):
        return {
            "idcliente": self.idcliente,
            "alegra_id": self.alegra_id,
            "code": self.code,
            "name": self.name,
            "type": self.type,
            "categoria_id": self.categoria_id,
            "cuenta_inventario_id": self.cuenta_inventario_id,
            "cuenta_costo_venta_id": self.cuenta_costo_venta_id,
            "impuestos": self.impuestos,
            "precios": self.precios,
            "bodegas": self.bodegas,
        }


class AlegraVendedor(db.Model):
    __tablename__ = "alegra_vendedores"

    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    alegra_id = db.Column(db.String(50), nullable=False)

    nombre = db.Column(db.String(255), nullable=False)
    identificacion = db.Column(db.String(50))
    activo = db.Column(db.Boolean, default=True)

    __table_args__ = (
        db.PrimaryKeyConstraint("idcliente", "alegra_id"),
    )

    def as_dict(self):
        return {
            "idcliente": self.idcliente,
            "alegra_id": self.alegra_id,
            "nombre": self.nombre,
            "identificacion": self.identificacion,
            "activo": self.activo,
        }


class AlegraCentroCosto(db.Model):
    __tablename__ = "alegra_centros_costo"

    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    alegra_id = db.Column(db.String(50), nullable=False)

    nombre = db.Column(db.String(255), nullable=False)
    codigo = db.Column(db.String(50))

    __table_args__ = (
        db.PrimaryKeyConstraint("idcliente", "alegra_id"),
    )

    def as_dict(self):
        return {
            "idcliente": self.idcliente,
            "alegra_id": self.alegra_id,
            "nombre": self.nombre,
            "codigo": self.codigo,
        }


class AlegraRetencionCatalogo(db.Model):
    __tablename__ = "alegra_retenciones_catalogo"

    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    alegra_id = db.Column(db.String(50), nullable=False)

    name = db.Column(db.String(255))
    type = db.Column(db.String(20))  # FUENTE | IVA | ICA
    percentage = db.Column(db.Numeric(9, 4))
    id_retention_reference = db.Column(db.String(50))  # agrupa por tipo de retencion matriz
    status = db.Column(db.String(20))  # incluye 'inactive'

    __table_args__ = (
        db.PrimaryKeyConstraint("idcliente", "alegra_id"),
    )

    def as_dict(self):
        return {
            "idcliente": self.idcliente,
            "alegra_id": self.alegra_id,
            "name": self.name,
            "type": self.type,
            "percentage": float(self.percentage or 0),
            "id_retention_reference": self.id_retention_reference,
            "status": self.status,
        }


class AlegraImpuestoCatalogo(db.Model):
    __tablename__ = "alegra_impuestos_catalogo"

    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    alegra_id = db.Column(db.String(50), nullable=False)

    name = db.Column(db.String(255))
    percentage = db.Column(db.Numeric(9, 4))
    type = db.Column(db.String(30))
    rate = db.Column(db.String(20))  # EXEMPT | EXCLUDED | null - distincion legal real (exento vs excluido)

    __table_args__ = (
        db.PrimaryKeyConstraint("idcliente", "alegra_id"),
    )

    def as_dict(self):
        return {
            "idcliente": self.idcliente,
            "alegra_id": self.alegra_id,
            "name": self.name,
            "percentage": float(self.percentage or 0),
            "type": self.type,
            "rate": self.rate,
        }


# ---------------------------------------------------------------------------
# 4.4 Unificacion de reporting — revisado 2026-07-08 contra la BD real (ver
# seccion 4.4 del plan maestro). NO se crean tablas fisicas "unificadas":
#
# - Ventas/CxC/Compras/CxP: se extienden las vistas ya existentes en produccion
#   (facturas_enriquecidas, ventas_movimientos_enriquecidos,
#   vw_siigo_compras_con_ajustes) con una rama UNION ALL nueva sobre
#   alegra_facturas/alegra_notas_credito/alegra_compras. No requiere clases
#   SQLAlchemy propias (las vistas no se mapean como db.Model aqui, igual que
#   las 4 vistas de Siigo tampoco lo estan).
# - Contable (P&L/balance/IVA/retenciones): el conector inserta directamente
#   en la tabla `AuxiliarContable` ya existente en models.py (con
#   cuenta_codigo real, solo para clientes Alegra con codificacion PUC) — no
#   se crea una tabla paralela.
# - Productos: pendiente confirmar si existe una fuente real que unificar
#   antes de decidir si hace falta una tabla fisica aqui.
# ---------------------------------------------------------------------------
