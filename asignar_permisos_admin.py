from app import create_app, db
from models import Perfil, Permiso, PerfilPermiso

app = create_app()

with app.app_context():
    perfiles_admin = Perfil.query.filter_by(nombre="Administrador").all()
    for perfil in perfiles_admin:
        print(f"Asignando permisos al perfil Administrador del cliente {perfil.idcliente}...")
        permisos = Permiso.query.filter_by(idcliente=perfil.idcliente, activo=True).all()
        for permiso in permisos:
            existe = PerfilPermiso.query.filter_by(
                idcliente=perfil.idcliente,
                idperfil=perfil.idperfil,
                idpermiso=permiso.idpermiso
            ).first()
            if not existe:
                nuevo = PerfilPermiso(
                    idcliente=perfil.idcliente,
                    idperfil=perfil.idperfil,
                    idpermiso=permiso.idpermiso,
                    permitido=True
                )
                db.session.add(nuevo)
                print(f"  ✅ {permiso.codigo}")
        db.session.commit()

print("🎯 Todos los permisos asignados correctamente a los perfiles Administrador.")
