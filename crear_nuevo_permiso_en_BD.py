from models import Permiso, db
clientes = Cliente.query.all()
for c in clientes:
    existe = Permiso.query.filter_by(idcliente=c.idcliente, codigo="ver_reporte_cruce_iva").first()
    if not existe:
        nuevo = Permiso(
            idcliente=c.idcliente,
            codigo="ver_reporte_cruceivas",
            nombre="Ver reporte Cruce de IVA",
            descripcion="Permite ver el reporte de cruces de IVA",
            activo=True
        )
        db.session.add(nuevo)
db.session.commit()
