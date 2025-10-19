import requests
from models import db, SiigoCompra, SiigoCompraItem, SiigoCredencial, SiigoProveedor
from utils import _siigo_auth_json_for_client, _siigo_headers_bearer

# Función sync_compras_desde_siigo() que extrae compras desde /v1/purchases
def sync_compras_desde_siigo(idcliente: int, deep: bool = False, batch_size: int = 50, only_missing: bool = True, since: str = None):
    cfg = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
    if not cfg:
        return {"error": "Credenciales Siigo no configuradas"}

    auth_data = _siigo_auth_json_for_client(cfg)
    if not isinstance(auth_data, dict):
        return {"error": "Respuesta inesperada del auth de Siigo", "detalle": str(auth_data)}

    token = auth_data.get("access_token")
    if not token:
        return {"error": "No se obtuvo access_token", "detalle": auth_data}

    headers = _siigo_headers_bearer(token)
    base_url = cfg.base_url.rstrip("/")

    nuevas = 0
    actualizadas = 0
    page = 1

    while True:
        url = f"{base_url}/v1/purchases?page_size={batch_size}&page={page}"
        print(f"📄 Consultando página {page} - URL: {url}")
        r = requests.get(url, headers=headers, timeout=60)

        try:
            data = r.json()
        except ValueError:
            return {"error": f"Respuesta no JSON al consultar compras (HTTP {r.status_code})", "detalle": r.text}

        if r.status_code != 200:
            return {"error": f"Error {r.status_code} al consultar compras", "detalle": r.text}

        items = data.get("results", [])
        print(f"✅ Compras recibidas en esta página: {len(items)}")

        if not items:
            break

        for c in items:
            idcompra = c.get("name")
            if not idcompra:
                print(f"⚠️ Sin 'name' para construir idcompra, datos: {c}")
                continue

            print(f"➡️ Procesando compra: {idcompra}")

            fecha = c.get("date")
            metadata = c.get("metadata", {})
            creado = metadata.get("created")

            payments = c.get("payments", [])
            venc = payments[0].get("due_date") if payments and isinstance(payments[0], dict) else None

            estado = c.get("status")

            supplier_data = c.get("supplier", {}) or {}
            proveedor_nombre = supplier_data.get("name")
            proveedor_identificacion = supplier_data.get("identification")

            # Buscar proveedor local si existe
            proveedor_nombre_local = None
            if proveedor_identificacion:
                proveedor = db.session.execute(
                    db.select(SiigoProveedor.nombre).where(
                        SiigoProveedor.idcliente == idcliente,
                        SiigoProveedor.identificacion == proveedor_identificacion
                    ).limit(1)
                ).scalar()

                if proveedor:
                    proveedor_nombre_local = proveedor

            # Elegir nombre proveedor: preferimos el local si existe
            nombre_final = proveedor_nombre_local or proveedor_nombre

            total = c.get("total")
            saldo = c.get("balance")
            cost_center = c.get("cost_center")  # ya es int

            provider_invoice = c.get("provider_invoice")
            factura_proveedor = None
            if provider_invoice:
                numero = provider_invoice.get("number")
                prefijo = provider_invoice.get("prefix")
                if numero and prefijo:
                    factura_proveedor = f"{prefijo}-{numero}"

            compra = SiigoCompra.query.filter_by(idcliente=idcliente, idcompra=idcompra).first()
            if not compra:
                compra = SiigoCompra(
                    idcliente=idcliente,
                    idcompra=idcompra,
                    fecha=fecha,
                    vencimiento=venc,
                    estado=estado,
                    proveedor_nombre=nombre_final,
                    proveedor_identificacion=proveedor_identificacion,
                    total=total,
                    saldo=saldo,
                    cost_center=cost_center,
                    creado=creado,
                    factura_proveedor=factura_proveedor
                )
                db.session.add(compra)
                nuevas += 1
                print(f"🌟 Nueva compra agregada: {idcompra}")
            else:
                compra.fecha = fecha
                compra.vencimiento = venc
                compra.estado = estado
                compra.proveedor_nombre = nombre_final
                compra.proveedor_identificacion = proveedor_identificacion
                compra.total = total
                compra.saldo = saldo
                compra.cost_center = cost_center
                compra.creado = creado
                compra.factura_proveedor = factura_proveedor
                actualizadas += 1
                print(f"🔁 Compra actualizada: {idcompra}")

            db.session.flush()
            SiigoCompraItem.query.filter_by(compra_id=compra.id).delete()

            for item in c.get("items", []):
                descripcion = item.get("description")
                cantidad = item.get("quantity")
                precio = item.get("price")
                code = item.get("code")
                impuestos = None
                taxes = item.get("taxes")
                if isinstance(taxes, list) and taxes:
                    impuestos = taxes[0].get("value")

                i = SiigoCompraItem(
                    compra_id=compra.id,
                    idcliente=idcliente,  # ✅ obligatorio ahora
                    descripcion=descripcion,
                    cantidad=cantidad,
                    precio=precio,
                    impuestos=impuestos,
                    codigo=code
                )
                db.session.add(i)

        db.session.commit()
        page += 1

    print(f"\n✅ FINALIZADO: Nuevas: {nuevas} | Actualizadas: {actualizadas} | Total: {nuevas + actualizadas}")
    return {
        "nuevas": nuevas,
        "actualizadas": actualizadas,
        "total": nuevas + actualizadas
    }