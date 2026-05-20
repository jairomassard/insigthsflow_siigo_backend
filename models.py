from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKeyConstraint
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Numeric, TIMESTAMP

db = SQLAlchemy()

class Cliente(db.Model):
    __tablename__ = "clientes"

    idcliente = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    nit = db.Column(db.String(50))
    email = db.Column(db.String(200))
    activo = db.Column(db.Boolean, default=True)

    # estos campos ya existen en tu tabla:
    pais = db.Column(db.String(80))
    ciudad = db.Column(db.String(120))
    direccion = db.Column(db.String(200))
    telefono1 = db.Column(db.String(50))
    logo_url = db.Column(db.String(300))
    limite_usuarios = db.Column(db.Integer)
    limite_sesiones = db.Column(db.Integer)
    timezone = db.Column(db.String(50), default="America/Bogota")


    # 👇 usar el nombre real en BD
    created_at = db.Column(db.DateTime, server_default=func.now())

    def as_dict(self):
        return {
            "idcliente": self.idcliente,
            "nombre": self.nombre,
            "nit": self.nit,
            "email": self.email,
            "activo": self.activo,
            "pais": self.pais,
            "ciudad": self.ciudad,
            "direccion": self.direccion,
            "telefono1": self.telefono1,
            "logo_url": self.logo_url,
            "limite_usuarios": self.limite_usuarios,
            "limite_sesiones": self.limite_sesiones,
            "timezone": self.timezone,
            # opcional: "created_at": self.created_at.isoformat() if self.created_at else None
        }


class Perfil(db.Model):
    __tablename__ = "perfiles"
    idperfil = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def as_dict(self):
        return {
            "idperfil": self.idperfil,
            "idcliente": self.idcliente,
            "nombre": self.nombre,
            "descripcion": self.descripcion,
            "created_at": self.created_at
        }

class Usuario(db.Model):
    __tablename__ = "usuarios"

    idusuario = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente"), nullable=True)
    idperfil = db.Column(db.Integer, db.ForeignKey("perfiles.idperfil"), nullable=True)
    nombre = db.Column(db.String(120), nullable=False)
    apellido = db.Column(db.String(120))  # NUEVO
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    activo = db.Column(db.Boolean, default=True)

    def as_dict(self):
        return {
            "idusuario": self.idusuario,
            "idcliente": self.idcliente,
            "idperfil": self.idperfil,
            "nombre": self.nombre,
            "apellido": self.apellido,
            "email": self.email,
            "activo": self.activo,
        }


class Permiso(db.Model):
    __tablename__ = 'permisos'
    idpermiso = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey('clientes.idcliente', ondelete='CASCADE'))
    nombre = db.Column(db.String(100), nullable=False)
    codigo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text)
    activo = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('idcliente', 'codigo', name='uq_cliente_codigo_permiso'),)

class PerfilPermiso(db.Model):
    __tablename__ = 'perfil_permisos'
    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey('clientes.idcliente', ondelete='CASCADE'))
    idperfil = db.Column(db.Integer, db.ForeignKey('perfiles.idperfil', ondelete='CASCADE'))
    idpermiso = db.Column(db.Integer, db.ForeignKey('permisos.idpermiso', ondelete='CASCADE'))
    permitido = db.Column(db.Boolean, default=True)

    __table_args__ = (db.UniqueConstraint('idcliente', 'idperfil', 'idpermiso', name='uq_cliente_perfil_permiso'),)



class PaqueteInsightflow(db.Model):
    __tablename__ = "paquetes_insightflow"

    idpaquete = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(80), unique=True, nullable=False)
    nombre = db.Column(db.String(150), nullable=False)
    descripcion = db.Column(db.Text)
    activo = db.Column(db.Boolean, default=True)
    es_modulo_adicional = db.Column(db.Boolean, default=False)
    orden = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def as_dict(self):
        return {
            "idpaquete": self.idpaquete,
            "codigo": self.codigo,
            "nombre": self.nombre,
            "descripcion": self.descripcion,
            "activo": self.activo,
            "es_modulo_adicional": self.es_modulo_adicional,
            "orden": self.orden,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class PaquetePermiso(db.Model):
    __tablename__ = "paquete_permisos"

    id = db.Column(db.Integer, primary_key=True)
    idpaquete = db.Column(
        db.Integer,
        db.ForeignKey("paquetes_insightflow.idpaquete", ondelete="CASCADE"),
        nullable=False
    )
    codigo_permiso = db.Column(db.String(100), nullable=False)
    activo = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("idpaquete", "codigo_permiso", name="uq_paquete_codigo_permiso"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idpaquete": self.idpaquete,
            "codigo_permiso": self.codigo_permiso,
            "activo": self.activo,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ClientePaquete(db.Model):
    __tablename__ = "cliente_paquetes"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(
        db.Integer,
        db.ForeignKey("clientes.idcliente", ondelete="CASCADE"),
        nullable=False
    )
    idpaquete = db.Column(
        db.Integer,
        db.ForeignKey("paquetes_insightflow.idpaquete", ondelete="CASCADE"),
        nullable=False
    )
    activo = db.Column(db.Boolean, default=True)
    fecha_inicio = db.Column(db.Date)
    fecha_fin = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("idcliente", "idpaquete", name="uq_cliente_paquete"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "idpaquete": self.idpaquete,
            "activo": self.activo,
            "fecha_inicio": self.fecha_inicio.isoformat() if self.fecha_inicio else None,
            "fecha_fin": self.fecha_fin.isoformat() if self.fecha_fin else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }



class SesionActiva(db.Model):
    __tablename__ = "sesiones_activas"
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.Text, unique=True, nullable=False)
    idusuario = db.Column(db.Integer, nullable=False)
    idcliente = db.Column(db.Integer, nullable=True)
    emitido_en = db.Column(db.DateTime, server_default=func.now())
    expira_en = db.Column(db.DateTime, nullable=True)



class SiigoCredencial(db.Model):
    __tablename__ = "siigo_credenciales"
    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), unique=True, nullable=False)
    base_url = db.Column(db.String(300))
    client_id = db.Column(db.Text)
    client_secret = db.Column(db.LargeBinary)  # cifrado
    username = db.Column(db.Text)
    password = db.Column(db.LargeBinary)       # cifrado
    partner_id = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())



class SiigoFactura(db.Model):
    __tablename__ = "siigo_facturas"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(
        db.Integer,
        db.ForeignKey("clientes.idcliente", ondelete="CASCADE"),
        nullable=False,
    )
    idfactura = db.Column(db.String(50), nullable=False)

    # Campos originales
    fecha = db.Column(db.Date)                      # NOT NULL en BD, pero ORM puede manejar None si aún no seteas valor
    vencimiento = db.Column(db.Date)
    cliente_nombre = db.Column(db.String(200))
    vendedor = db.Column(db.String(200))
    estado = db.Column(db.String(50))
    total = db.Column(db.Numeric(15, 2))
    saldo = db.Column(db.Numeric(15, 2))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Nuevos metadatos / económicos
    siigo_uuid = db.Column(db.Text)
    customer_id = db.Column(UUID(as_uuid=True))
    customer_identificacion = db.Column(db.Text)
    seller_id = db.Column(db.Integer)
    moneda = db.Column(db.Text)

    subtotal = db.Column(db.Numeric(18, 2))
    impuestos_total = db.Column(db.Numeric(18, 2))
    descuentos_total = db.Column(db.Numeric(18, 2))
    pagos_total = db.Column(db.Numeric(18, 2))
    saldo_calculado = db.Column(db.Numeric(18, 2))

    estado_pago = db.Column(db.Text)     # 'pagada' | 'parcial' | 'pendiente'
    medio_pago = db.Column(db.Text)
    observaciones = db.Column(db.Text)

    metadata_created = db.Column(db.DateTime)  # timestamp sin zona en BD
    metadata_updated = db.Column(db.DateTime)

    public_url = db.Column(db.Text)
    cost_center = db.Column(db.Integer)
    retenciones = db.Column(db.JSON)  # Lista de retenciones generales: dicts con type, percentage, value

    # Relación con ítems (con borrado en cascada)
    items = db.relationship(
        "SiigoFacturaItem",
        backref="factura",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    __table_args__ = (
        db.UniqueConstraint("idcliente", "idfactura"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "idfactura": self.idfactura,
            "fecha": self.fecha.isoformat() if self.fecha else None,
            "vencimiento": self.vencimiento.isoformat() if self.vencimiento else None,
            "cliente_nombre": self.cliente_nombre,
            "vendedor": self.vendedor,
            "estado": self.estado,
            "total": float(self.total) if self.total is not None else None,
            "saldo": float(self.saldo) if self.saldo is not None else None,
            "siigo_uuid": self.siigo_uuid,
            "customer_id": self.customer_id,
            "customer_identificacion": self.customer_identificacion,
            "seller_id": self.seller_id,
            "moneda": self.moneda,
            "subtotal": float(self.subtotal) if self.subtotal is not None else None,
            "impuestos_total": float(self.impuestos_total) if self.impuestos_total is not None else None,
            "descuentos_total": float(self.descuentos_total) if self.descuentos_total is not None else None,
            "pagos_total": float(self.pagos_total) if self.pagos_total is not None else None,
            "saldo_calculado": float(self.saldo_calculado) if self.saldo_calculado is not None else None,
            "estado_pago": self.estado_pago,
            "medio_pago": self.medio_pago,
            "observaciones": self.observaciones,
            "metadata_created": self.metadata_created.isoformat() if self.metadata_created else None,
            "metadata_updated": self.metadata_updated.isoformat() if self.metadata_updated else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "public_url": self.public_url,
            "cost_center": self.cost_center,
            "retenciones": self.retenciones,
        }


class SiigoFacturaItem(db.Model):
    __tablename__ = "siigo_factura_items"

    id = db.Column(db.Integer, primary_key=True)
    factura_id = db.Column(
        db.Integer,
        db.ForeignKey("siigo_facturas.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Campos originales
    descripcion = db.Column(db.String(2000))
    cantidad = db.Column(db.Numeric(15, 2))
    precio = db.Column(db.Numeric(15, 2))
    impuestos = db.Column(db.Numeric(15, 2))  # compatibilidad (puedes mapear IVA aquí)

    # Nuevos
    producto_id = db.Column(db.Text)
    codigo = db.Column(db.Text)
    sku = db.Column(db.Text)

    iva_porcentaje = db.Column(db.Numeric(9, 2))
    iva_valor = db.Column(db.Numeric(18, 2))
    descuento_valor = db.Column(db.Numeric(18, 2))
    total_item = db.Column(db.Numeric(18, 2))

    retenciones_item = db.Column(db.JSON)  # Lista de dicts con {type, percentage, value}

    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)


    def as_dict(self):
        return {
            "id": self.id,
            "factura_id": self.factura_id,
            "idcliente": self.idcliente,  # ✅ nuevo campo
            "descripcion": self.descripcion,
            "cantidad": float(self.cantidad) if self.cantidad is not None else None,
            "precio": float(self.precio) if self.precio is not None else None,
            "impuestos": float(self.impuestos) if self.impuestos is not None else None,
            "producto_id": self.producto_id,
            "codigo": self.codigo,
            "sku": self.sku,
            "iva_porcentaje": float(self.iva_porcentaje) if self.iva_porcentaje is not None else None,
            "iva_valor": float(self.iva_valor) if self.iva_valor is not None else None,
            "descuento_valor": float(self.descuento_valor) if self.descuento_valor is not None else None,
            "total_item": float(self.total_item) if self.total_item is not None else None,
            "retenciones_item": self.retenciones_item,
        }
    

class SiigoVendedor(db.Model):
    __tablename__ = "siigo_vendedores"

    id = db.Column(db.Integer, nullable=False)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    nombre = db.Column(db.Text, nullable=False)
    activo = db.Column(db.Boolean, default=True)
    metadata_json = db.Column("metadata", db.JSON)

    __table_args__ = (
        db.PrimaryKeyConstraint('idcliente', 'id'),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "nombre": self.nombre,
            "activo": self.activo,
            "metadata": self.metadata_json,
        }



class SiigoCentroCosto(db.Model):
    __tablename__ = "siigo_centros_costo"

    id = db.Column(db.Integer, nullable=False)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    nombre = db.Column(db.Text, nullable=False)
    codigo = db.Column(db.Text)
    activo = db.Column(db.Boolean, default=True)
    metadata_json = db.Column("metadata", db.JSON)

    __table_args__ = (
        db.PrimaryKeyConstraint('idcliente', 'id'),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "nombre": self.nombre,
            "codigo": self.codigo,
            "activo": self.activo,
            "metadata": self.metadata_json,
        }




class SiigoCustomer(db.Model):
    __tablename__ = "siigo_customers"

    id = db.Column(UUID(as_uuid=True), nullable=False)
    idcliente = db.Column(db.Integer, nullable=False)

    __table_args__ = (
        db.PrimaryKeyConstraint('idcliente', 'id'),  # ← ✅ clave primaria compuesta
    )

    identification = db.Column(db.String(50))
    name = db.Column(db.String(255))
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    branch_office = db.Column(db.Integer)
    email = db.Column(db.String(200))
    phone = db.Column(db.String(100))
    address = db.Column(JSONB)
    contacts = db.Column(JSONB)
    metadata_json = db.Column("metadata", JSONB)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<SiigoCustomer {self.id} - {self.name or self.identification}>"



class SiigoNotaCredito(db.Model):
    __tablename__ = "siigo_notas_credito"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)

    nota_id = db.Column(db.String(50), nullable=False)
    uuid = db.Column(db.String(50))  # antes siigo_uuid
    fecha = db.Column(db.Date)
    total = db.Column(db.Numeric(15, 2))  # antes valor_total
    estado = db.Column(db.String(50))
    motivo = db.Column(db.Text)
    observaciones = db.Column(db.Text)
    cliente_nombre = db.Column(db.String(200))
    customer_id = db.Column(db.String(50))  # antes UUID(as_uuid=True)

    factura_afectada_id = db.Column(db.String(50))
    factura_afectada_uuid = db.Column(db.String(50))   # <-- 🔥 agregar esto
    metadata_json = db.Column(db.JSON)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("idcliente", "nota_id"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "nota_id": self.nota_id,
            "uuid": self.uuid,
            "fecha": self.fecha.isoformat() if self.fecha else None,
            "total": float(self.total or 0),
            "estado": self.estado,
            "motivo": self.motivo,
            "observaciones": self.observaciones,
            "cliente_nombre": self.cliente_nombre,
            "customer_id": self.customer_id,
            "factura_afectada_id": self.factura_afectada_id,
            "factura_afectada_uuid": self.factura_afectada_uuid,   # <-- 🔥 agregar también aquí
            "metadata_json": self.metadata_json,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }



class SiigoPagoProveedor(db.Model):
    __tablename__ = "siigo_pagos_proveedores"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    idpago = db.Column(db.String(50), nullable=False)
    fecha = db.Column(db.Date, nullable=False)
    proveedor_identificacion = db.Column(db.String(50))
    proveedor_nombre = db.Column(db.String(200))
    metodo_pago = db.Column(db.String(100))
    valor = db.Column(db.Numeric(15, 2))
    factura_aplicada = db.Column(db.String(50))
    factura_pagada = db.Column(db.String(10))  # SI, NO, PARCIAL
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("idcliente", "idpago", "factura_aplicada"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "idpago": self.idpago,
            "fecha": self.fecha.isoformat() if self.fecha else None,
            "proveedor_identificacion": self.proveedor_identificacion,
            "proveedor_nombre": self.proveedor_nombre,
            "metodo_pago": self.metodo_pago,
            "valor": float(self.valor) if self.valor else None,
            "factura_aplicada": self.factura_aplicada,
            "factura_pagada": self.factura_pagada,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }



class SiigoCompra(db.Model):
    __tablename__ = "siigo_compras"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    idcompra = db.Column(db.String(50), nullable=False)
    fecha = db.Column(db.Date, nullable=False)
    vencimiento = db.Column(db.Date)
    proveedor_nombre = db.Column(db.String(200))  # nombre visible
    proveedor_identificacion = db.Column(db.String(50))  # nuevo: NIT
    estado = db.Column(db.String(50))
    total = db.Column(db.Numeric(15, 2))
    saldo = db.Column(db.Numeric(15, 2))
    created_at = db.Column(db.DateTime, server_default=func.now())
    cost_center = db.Column(db.Integer)
    creado = db.Column(db.DateTime)
    factura_proveedor = db.Column(db.String(100))  # nueva columna

    items = db.relationship(
        "SiigoCompraItem",
        backref="compra",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    __table_args__ = (
        db.UniqueConstraint("idcliente", "idcompra"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "idcompra": self.idcompra,
            "fecha": self.fecha.isoformat() if self.fecha else None,
            "vencimiento": self.vencimiento.isoformat() if self.vencimiento else None,
            "proveedor_nombre": self.proveedor_nombre,
            "proveedor_identificacion": self.proveedor_identificacion,
            "estado": self.estado,
            "total": float(self.total or 0),
            "saldo": float(self.saldo or 0),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "cost_center": self.cost_center,
            "creado": self.creado.isoformat() if self.creado else None,
            "factura_proveedor": self.factura_proveedor,
        }



class SiigoCompraItem(db.Model):
    __tablename__ = "siigo_compras_items"

    id = db.Column(db.Integer, primary_key=True)
    compra_id = db.Column(db.Integer, db.ForeignKey("siigo_compras.id", ondelete="CASCADE"), nullable=False)
    descripcion = db.Column(db.String(2000))
    cantidad = db.Column(db.Numeric(15, 2))
    precio = db.Column(db.Numeric(15, 2))
    impuestos = db.Column(db.Numeric(15, 2))
    codigo = db.Column(db.String(100))
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)



    def as_dict(self):
        return {
            "id": self.id,
            "compra_id": self.compra_id,
            "idcliente": self.idcliente,  # ✅ nuevo campo
            "descripcion": self.descripcion,
            "cantidad": float(self.cantidad or 0),
            "precio": float(self.precio or 0),
            "impuestos": float(self.impuestos or 0),
            "codigo": self.codigo,

        }



class SiigoProveedor(db.Model):
    __tablename__ = "siigo_proveedores"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)

    nombre = db.Column(db.String(200), nullable=False)
    tipo_identificacion = db.Column(db.String(100))
    identificacion = db.Column(db.String(50), nullable=False)
    digito_verificacion = db.Column(db.String(10))
    direccion = db.Column(db.String(200))
    ciudad = db.Column(db.String(100))
    telefono = db.Column(db.String(100))
    estado = db.Column(db.String(50))

    created_at = db.Column(db.DateTime, server_default=func.now())

    __table_args__ = (
        db.UniqueConstraint("idcliente", "identificacion"),
    )

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "nombre": self.nombre,
            "tipo_identificacion": self.tipo_identificacion,
            "identificacion": self.identificacion,
            "digito_verificacion": self.digito_verificacion,
            "direccion": self.direccion,
            "ciudad": self.ciudad,
            "telefono": self.telefono,
            "estado": self.estado,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }




class SiigoCuentasPorCobrar(db.Model):
    __tablename__ = "siigo_cuentasporcobrar"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    
    documento = db.Column(db.String(50))
    fecha = db.Column(db.Date)                # viene de siigo_compras (Botón 2)
    fecha_vencimiento = db.Column(db.Date)    # viene del endpoint cuentas por pagar
    
    proveedor_identificacion = db.Column(db.String(50))
    proveedor_nombre = db.Column(db.String(300))
    
    valor = db.Column(db.Numeric(18, 2))
    saldo = db.Column(db.Numeric(18, 2))
    
    centro_costo = db.Column(db.String(200))
    
    idcompra = db.Column(db.String(50), nullable=True)  # ahora String, no Integer

    created_at = db.Column(db.DateTime, server_default=func.now())

    # 🔑 ForeignKey compuesta
    __table_args__ = (
        ForeignKeyConstraint(
            ["idcliente", "idcompra"],
            ["siigo_compras.idcliente", "siigo_compras.idcompra"],
            ondelete="CASCADE"
        ),
    )


class SiigoNomina(db.Model):
    __tablename__ = "siigo_nomina"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, nullable=False)
    periodo = db.Column(db.Date, nullable=False)
    nombre = db.Column(db.String(255))
    identificacion = db.Column(db.String(50))
    no_contrato = db.Column(db.String(50))
    sueldo = db.Column(db.Numeric(18, 2))
    aux_transporte = db.Column(db.Numeric(18, 2))
    auxilio_extralegal = db.Column(db.Numeric(18, 2))
    prima = db.Column(db.Numeric(18, 2), default=0)
    intereses_cesantias = db.Column(db.Numeric(18, 2), default=0)
    total_ingresos = db.Column(db.Numeric(18, 2))
    fondo_salud = db.Column(db.Numeric(18, 2))
    fondo_pension = db.Column(db.Numeric(18, 2))
    fondo_solidaridad = db.Column(db.Numeric(18, 2))
    retefuente = db.Column(db.Numeric(18, 2))
    prestamos = db.Column(db.Numeric(18, 2))
    total_deducciones = db.Column(db.Numeric(18, 2))
    neto_pagar = db.Column(db.Numeric(18, 2))
    creado = db.Column(db.DateTime, default=db.func.now())


class SiigoProducto(db.Model):
    __tablename__ = "siigo_productos"

    id = Column(UUID(as_uuid=True), primary_key=True)
    
    idcliente = db.Column(db.Integer, primary_key=True)  # <--- esto es lo que falta

    code = Column(String)
    name = Column(String)
    type = Column(String)

    account_group_id = Column(Integer)
    account_group_name = Column(String)

    unit_code = Column(String)
    unit_name = Column(String)
    unit_label = Column(String)

    tax_classification = Column(String)
    tax_included = Column(Boolean)

    active = Column(Boolean)
    stock_control = Column(Boolean)
    available_quantity = Column(Numeric)

    taxes = Column(JSONB)
    warehouses = Column(JSONB)
    additional_fields = Column(JSONB)

    metadata_created = Column(TIMESTAMP)
    metadata_updated = Column(TIMESTAMP)

    __table_args__ = (
        db.PrimaryKeyConstraint('id', 'idcliente'),
    )




class BalancePrueba(db.Model):
    __tablename__ = "balance_prueba"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, nullable=False)
    codigo_cuenta = db.Column(db.String(50))
    nombre_cuenta = db.Column(db.String(255))
    nivel = db.Column(db.String(50))
    es_transaccional = db.Column(db.Boolean)
    saldo_inicial = db.Column(db.Numeric(18, 2))
    movimiento_debito = db.Column(db.Numeric(18, 2))
    movimiento_credito = db.Column(db.Numeric(18, 2))
    saldo_final = db.Column(db.Numeric(18, 2))
    periodo_anio = db.Column(db.Integer)
    periodo_mes_inicio = db.Column(db.Integer)
    periodo_mes_fin = db.Column(db.Integer)
    fecha_carga = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Convierte la instancia en un diccionario JSON serializable."""
        return {
            "id": self.id,
            "codigo_cuenta": self.codigo_cuenta,
            "nombre_cuenta": self.nombre_cuenta,
            "nivel": self.nivel,
            "es_transaccional": self.es_transaccional,
            "saldo_inicial": float(self.saldo_inicial or 0),
            "movimiento_debito": float(self.movimiento_debito or 0),
            "movimiento_credito": float(self.movimiento_credito or 0),
            "saldo_final": float(self.saldo_final or 0),
            "periodo_anio": self.periodo_anio,
            "periodo_mes_inicio": self.periodo_mes_inicio,
            "periodo_mes_fin": self.periodo_mes_fin,
            "fecha_carga": self.fecha_carga.isoformat() if self.fecha_carga else None,
        }



class SiigoSyncConfig(db.Model):
    __tablename__ = "siigo_sync_config"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    hora_ejecucion = db.Column(db.Time, nullable=False)
    frecuencia_dias = db.Column(db.Integer, default=1)
    activo = db.Column(db.Boolean, default=True)
    ultimo_ejecutado = db.Column(db.DateTime(timezone=True))
    resultado_ultima_sync = db.Column(db.Text)
    detalle_ultima_sync = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    # Fecha inicial para insertar Documentos Soporte API desde staging hacia siigo_compras.
    # Si es NULL, no se limita por fecha.
    ds_fecha_desde = db.Column(db.Date, nullable=True)
    sync_fecha_desde = db.Column(db.Date, nullable=True)
    ultimo_auto_ejecutado = db.Column(db.DateTime(timezone=True))

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "hora_ejecucion": self.hora_ejecucion.strftime("%H:%M") if self.hora_ejecucion else None,
            "frecuencia_dias": self.frecuencia_dias,
            "activo": self.activo,
            "ultimo_ejecutado": self.ultimo_ejecutado.isoformat() if self.ultimo_ejecutado else None,
            "resultado_ultima_sync": self.resultado_ultima_sync,
            "detalle_ultima_sync": self.detalle_ultima_sync,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "ds_fecha_desde": self.ds_fecha_desde.isoformat() if self.ds_fecha_desde else None,
            "sync_fecha_desde": self.sync_fecha_desde.isoformat() if self.sync_fecha_desde else None,
            "ultimo_auto_ejecutado": self.ultimo_auto_ejecutado.isoformat() if self.ultimo_auto_ejecutado else None,
        }   


class SiigoSyncLog(db.Model):
    __tablename__ = "siigo_sync_logs"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    fecha_programada = db.Column(db.DateTime(timezone=True), nullable=False)
    ejecutado_en = db.Column(db.DateTime(timezone=True))
    resultado = db.Column(db.Text)
    detalle = db.Column(db.Text)
    creado_en = db.Column(db.DateTime(timezone=True), server_default=func.now())

    # Nuevos campos para historial amigable
    origen = db.Column(db.String(20))
    total_pasos = db.Column(db.Integer, default=0)
    pasos_ok = db.Column(db.Integer, default=0)
    pasos_error = db.Column(db.Integer, default=0)
    endpoint_fallido = db.Column(db.Text)

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "fecha_programada": self.fecha_programada.isoformat() if self.fecha_programada else None,
            "ejecutado_en": self.ejecutado_en.isoformat() if self.ejecutado_en else None,
            "resultado": self.resultado,
            "detalle": self.detalle,
            "creado_en": self.creado_en.isoformat() if self.creado_en else None,
            "origen": self.origen,
            "total_pasos": self.total_pasos or 0,
            "pasos_ok": self.pasos_ok or 0,
            "pasos_error": self.pasos_error or 0,
            "endpoint_fallido": self.endpoint_fallido,
        }


class SiigoSyncMetric(db.Model):
    __tablename__ = "siigo_sync_metrics"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente", ondelete="CASCADE"), nullable=False)
    endpoint = db.Column(db.Text, nullable=False)
    duracion_segundos = db.Column(db.Numeric(8, 2))
    status_code = db.Column(db.Integer)
    resultado = db.Column(db.Text)
    ejecutado_en = db.Column(db.DateTime(timezone=True), server_default=func.now())
    detalle_resumen = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def as_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "endpoint": self.endpoint,
            "duracion_segundos": float(self.duracion_segundos or 0),
            "status_code": self.status_code,
            "resultado": self.resultado,
            "ejecutado_en": self.ejecutado_en.isoformat() if self.ejecutado_en else None,
            "detalle_resumen": (self.detalle_resumen[:300] + "...") if self.detalle_resumen and len(self.detalle_resumen) > 300 else self.detalle_resumen,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }




class SystemNotification(db.Model):
    __tablename__ = "system_notifications"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, nullable=False)
    tipo = db.Column(db.String(50), default="INFO")  # Ej: 'SYNC_RESULT'
    titulo = db.Column(db.String(200))
    mensaje = db.Column(db.Text)
    nivel = db.Column(db.String(20), default="info")  # 'info', 'success', 'warning', 'error'
    leido = db.Column(db.Boolean, default=False)
    creado_en = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)

    def __repr__(self):
        return f"<SystemNotification id={self.id} cliente={self.idcliente} tipo={self.tipo}>"



class AuxiliarContable(db.Model):
    __tablename__ = "auxiliar_contable"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(db.Integer, db.ForeignKey("clientes.idcliente"), nullable=False)
    fecha_contable = db.Column(db.Date, nullable=False)
    comprobante_tipo = db.Column(db.String(20))
    comprobante_numero = db.Column(db.String(50))
    cuenta_codigo = db.Column(db.String(20), nullable=False)
    cuenta_nombre = db.Column(db.String(255))
    tercero_nit = db.Column(db.String(50))
    tercero_nombre = db.Column(db.String(255))
    detalle = db.Column(db.Text)
    debito = db.Column(db.Numeric(18, 2))
    credito = db.Column(db.Numeric(18, 2))
    base_gravable = db.Column(db.Numeric(18, 2))
    fecha_carga = db.Column(db.DateTime, default=datetime.utcnow)
    periodo_anio = db.Column(db.Integer)
    periodo_mes = db.Column(db.Integer)

    def to_dict(self):
        return {
            "fecha": self.fecha_contable.isoformat(),
            "cuenta": self.cuenta_codigo,
            "tercero": self.tercero_nombre,
            "debito": float(self.debito),
            "credito": float(self.credito),
            "base": float(self.base_gravable)
        }


from decimal import Decimal


class AuxiliarSaldosCorte(db.Model):
    __tablename__ = "auxiliar_saldos_corte"

    id = db.Column(db.Integer, primary_key=True)
    idcliente = db.Column(
        db.Integer,
        db.ForeignKey("clientes.idcliente", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    fecha_corte = db.Column(db.Date, nullable=False, index=True)
    cuenta_codigo = db.Column(db.String(20), nullable=False, index=True)
    cuenta_nombre = db.Column(db.String(255))
    cuenta_padre = db.Column(db.String(10))
    clase = db.Column(db.String(1))
    grupo = db.Column(db.String(2))
    seccion = db.Column(db.String(30), index=True)
    grupo_balance = db.Column(db.String(50), index=True)
    naturaleza = db.Column(db.String(30))
    saldo = db.Column(db.Numeric(18, 2), nullable=False, default=Decimal("0.00"))
    fecha_generacion = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    origen = db.Column(db.String(30), default="AUXILIAR")

    __table_args__ = (
        db.UniqueConstraint(
            "idcliente",
            "fecha_corte",
            "cuenta_codigo",
            name="uq_aux_saldos_corte_cliente_fecha_cuenta"
        ),
    )



class DashboardResumenConfig(db.Model):
    __tablename__ = "dashboard_resumen_config"

    id = db.Column(db.Integer, primary_key=True)

    idcliente = db.Column(
        db.Integer,
        db.ForeignKey("clientes.idcliente", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Activación / visibilidad
    activo = db.Column(db.Boolean, nullable=False, default=True)
    mostrar_caja = db.Column(db.Boolean, nullable=False, default=False)
    mostrar_runway = db.Column(db.Boolean, nullable=False, default=False)

    # Caja disponible
    modo_caja = db.Column(db.String(20), nullable=False, default="sin_configurar")
    cuentas_incluidas = db.Column(db.JSON)
    cuentas_excluidas = db.Column(db.JSON)

    # Runway
    modo_runway = db.Column(db.String(30), nullable=False, default="sin_configurar")
    meses_promedio_runway = db.Column(db.Integer, nullable=False, default=3)

    # Objetivos / metas
    meta_eficiencia_operativa = db.Column(
        db.Numeric(10, 2),
        nullable=False,
        default=Decimal("20.00")
    )
    meta_ebitda = db.Column(db.Numeric(18, 2))
    meta_margen_ebitda = db.Column(db.Numeric(10, 2))

    # Comportamiento visual / ejecutivo
    meses_grafica = db.Column(db.Integer, nullable=False, default=6)
    top_clientes = db.Column(db.Integer, nullable=False, default=5)
    top_proveedores = db.Column(db.Integer, nullable=False, default=5)
    top_gastos = db.Column(db.Integer, nullable=False, default=5)
    indicador_estrella = db.Column(
        db.String(50),
        nullable=False,
        default="eficiencia_operativa"
    )

    # Periodización
    modo_periodo_default = db.Column(
        db.String(30),
        nullable=False,
        default="ytd_cerrado"
    )

    # Auditoría
    creado_en = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    actualizado_en = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    __table_args__ = (
        db.UniqueConstraint(
            "idcliente",
            name="uq_dashboard_resumen_config_idcliente"
        ),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "activo": self.activo,
            "mostrar_caja": self.mostrar_caja,
            "mostrar_runway": self.mostrar_runway,
            "modo_caja": self.modo_caja,
            "cuentas_incluidas": self.cuentas_incluidas or [],
            "cuentas_excluidas": self.cuentas_excluidas or [],
            "modo_runway": self.modo_runway,
            "meses_promedio_runway": self.meses_promedio_runway,
            "meta_eficiencia_operativa": float(self.meta_eficiencia_operativa or 0),
            "meta_ebitda": float(self.meta_ebitda or 0) if self.meta_ebitda is not None else None,
            "meta_margen_ebitda": float(self.meta_margen_ebitda or 0) if self.meta_margen_ebitda is not None else None,
            "meses_grafica": self.meses_grafica,
            "top_clientes": self.top_clientes,
            "top_proveedores": self.top_proveedores,
            "top_gastos": self.top_gastos,
            "indicador_estrella": self.indicador_estrella,
            "modo_periodo_default": self.modo_periodo_default,
            "creado_en": self.creado_en.isoformat() if self.creado_en else None,
            "actualizado_en": self.actualizado_en.isoformat() if self.actualizado_en else None,
        }




class SiigoDocumentoSoporteApiStaging(db.Model):
    __tablename__ = "siigo_documentos_soporte_api_staging"

    id = db.Column(db.Integer, primary_key=True)

    idcliente = db.Column(
        db.Integer,
        db.ForeignKey("clientes.idcliente", ondelete="CASCADE"),
        nullable=False
    )

    siigo_id = db.Column(db.UUID(as_uuid=False), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    number = db.Column(db.Integer)
    document_id = db.Column(db.Integer)

    fecha = db.Column(db.Date)
    vencimiento = db.Column(db.Date)

    proveedor_siigo_id = db.Column(db.UUID(as_uuid=False))
    proveedor_identificacion = db.Column(db.String(50))
    proveedor_nombre = db.Column(db.String(200))

    cost_center = db.Column(db.Integer)

    total = db.Column(db.Numeric(15, 2))
    balance = db.Column(db.Numeric(15, 2))
    payment_value = db.Column(db.Numeric(15, 2))

    supplier_receipt_prefix = db.Column(db.String(50))
    supplier_receipt_number = db.Column(db.String(100))
    factura_proveedor = db.Column(db.String(100))

    stamp_status = db.Column(db.String(50))
    cuds = db.Column(db.Text)

    items_count = db.Column(db.Integer, default=0)
    retentions_total = db.Column(db.Numeric(15, 2), default=0)

    raw_json = db.Column(db.JSON, nullable=False)

    created_siigo = db.Column(db.DateTime)
    synced_at = db.Column(db.DateTime, server_default=db.func.now())



class IndicadoresFinancierosConfig(db.Model):
    __tablename__ = "indicadores_financieros_config"

    id = db.Column(db.Integer, primary_key=True)

    idcliente = db.Column(
        db.Integer,
        db.ForeignKey("clientes.idcliente", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    activo = db.Column(db.Boolean, nullable=False, default=True)

    # Liquidez
    liquidez_min = db.Column(db.Numeric(18, 4))
    liquidez_max = db.Column(db.Numeric(18, 4))

    # Endeudamiento / apalancamiento
    apalancamiento_max = db.Column(db.Numeric(18, 4))
    endeudamiento_largo_plazo_max = db.Column(db.Numeric(18, 4))

    # Rentabilidad
    rentabilidad_min = db.Column(db.Numeric(18, 4))

    # Solvencia / autonomía
    autonomia_min = db.Column(db.Numeric(18, 4))
    solvencia_min = db.Column(db.Numeric(18, 4))
    cobertura_activo_pasivo_min = db.Column(db.Numeric(18, 4))

    # Capital de trabajo
    capital_trabajo_min = db.Column(db.Numeric(18, 2))

    # Composición del balance
    porcentaje_pasivo_corto_max = db.Column(db.Numeric(18, 4))
    porcentaje_activo_no_corriente_max = db.Column(db.Numeric(18, 4))

    # Auditoría
    creado_por = db.Column(db.Integer)
    actualizado_por = db.Column(db.Integer)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    __table_args__ = (
        db.UniqueConstraint(
            "idcliente",
            name="uq_indicadores_financieros_config_idcliente"
        ),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "idcliente": self.idcliente,
            "activo": self.activo,

            "liquidez_min": float(self.liquidez_min) if self.liquidez_min is not None else None,
            "liquidez_max": float(self.liquidez_max) if self.liquidez_max is not None else None,
            "apalancamiento_max": float(self.apalancamiento_max) if self.apalancamiento_max is not None else None,
            "rentabilidad_min": float(self.rentabilidad_min) if self.rentabilidad_min is not None else None,
            "autonomia_min": float(self.autonomia_min) if self.autonomia_min is not None else None,
            "solvencia_min": float(self.solvencia_min) if self.solvencia_min is not None else None,
            "cobertura_activo_pasivo_min": float(self.cobertura_activo_pasivo_min) if self.cobertura_activo_pasivo_min is not None else None,
            "capital_trabajo_min": float(self.capital_trabajo_min) if self.capital_trabajo_min is not None else None,
            "porcentaje_pasivo_corto_max": float(self.porcentaje_pasivo_corto_max) if self.porcentaje_pasivo_corto_max is not None else None,
            "porcentaje_activo_no_corriente_max": float(self.porcentaje_activo_no_corriente_max) if self.porcentaje_activo_no_corriente_max is not None else None,
            "endeudamiento_largo_plazo_max": float(self.endeudamiento_largo_plazo_max) if self.endeudamiento_largo_plazo_max is not None else None,

            "creado_por": self.creado_por,
            "actualizado_por": self.actualizado_por,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }