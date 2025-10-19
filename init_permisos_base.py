from app import create_app, db
from models import Permiso, Cliente

app = create_app()

# --- permisos reales según layout ---
permisos_base = [
    ("ver_dashboard", "Ver Dashboard", "Permite acceder al panel principal del cliente"),

    ("ver_perfiles", "Ver Perfiles", "Permite ver perfiles del cliente"),
    ("editar_perfiles", "Editar Perfiles", "Permite crear/editar perfiles del cliente"),

    ("ver_usuarios", "Ver Usuarios", "Permite ver usuarios del cliente"),
    ("editar_usuarios", "Editar Usuarios", "Permite crear/editar usuarios del cliente"),

    ("ver_integracion_siigo", "Ver Integración Siigo", "Permite ver configuración de integración Siigo"),
    ("editar_integracion_siigo", "Editar Integración Siigo", "Permite configurar la integración con Siigo"),

    ("ver_reporte_ventas", "Ver Reporte de Ventas", "Permite ver ingresos por ventas"),
    ("ver_reporte_vendedores", "Ver Reporte de Vendedores", "Permite ver ventas por vendedor"),
    ("ver_reporte_productos", "Ver Reporte de Productos", "Permite ver ventas por producto"),

    ("ver_reporte_compras_gastos", "Ver Reporte de Compras/Gastos", "Permite ver egresos por compras y gastos"),
    ("ver_reporte_nomina", "Ver Reporte de Nómina", "Permite ver costos de nómina"),
    ("ver_reporte_proveedores", "Ver Reporte de Proveedores", "Permite ver compras a proveedores"),

    ("ver_reporte_clientes", "Ver Reporte de Clientes", "Permite ver facturación de clientes"),
    ("ver_reporte_cxc", "Ver Reporte CxC", "Permite ver cuentas por cobrar / cartera"),

    ("ver_reporte_consolidado", "Ver Reporte Consolidado", "Permite ver estados financieros consolidados"),
    ("ver_reporte_balance", "Ver Reporte Balance", "Permite ver análisis del balance de prueba"),
    ("ver_reporte_indicadores", "Ver Reporte Indicadores", "Permite ver indicadores financieros"),

    ("admin_panel", "Panel Admin", "Acceso al panel de superadministrador"),
]

with app.app_context():
    clientes = Cliente.query.all()
    for cliente in clientes:
        for codigo, nombre, descripcion in permisos_base:
            existe = Permiso.query.filter_by(idcliente=cliente.idcliente, codigo=codigo).first()
            if not existe:
                p = Permiso(
                    idcliente=cliente.idcliente,
                    codigo=codigo,
                    nombre=nombre,
                    descripcion=descripcion,
                    activo=True
                )
                db.session.add(p)
                print(f"✔️ {codigo} creado para cliente {cliente.nombre}")
    db.session.commit()
    print("✅ Permisos base actualizados correctamente.")
