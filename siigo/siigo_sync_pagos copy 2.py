# backend/siigo/siigo_sync_pagos.py
# --- Sincronización de pagos egresos desde Siigo (modo detallado con soporte para DS y FC) ---

import os
from datetime import datetime
from typing import List, Dict, Any, Optional

import requests
from models import db, Cliente, SiigoCredencial, SiigoPagoProveedor, SiigoCompra
from .siigo_sync_refactor import (
    dec_local, _d, _str,
    _request_with_retries, _headers_json, _headers_bearer,
    SiigoError
)

PARTNER_ID = os.getenv("SIIGO_PARTNER_ID", "ProjectManagerApp")
PAGE_SIZE = int(os.getenv("SIIGO_PAGE_SIZE", "100"))


def fetch_all_payment_receipts(base_url: str, token: str, page_size: int = PAGE_SIZE) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    page = 1
    while True:
        url = f"{base_url.rstrip('/')}/v1/payment-receipts?page={page}&page_size={page_size}"
        r = _request_with_retries("GET", url, headers=_headers_bearer(token))
        if r.status_code != 200:
            raise SiigoError(f"Payment Receipts {r.status_code}: {r.text}")
        data = r.json() or {}
        items = data.get("results") or []
        if not isinstance(items, list):
            raise SiigoError("Respuesta de /v1/payment-receipts no es una lista en 'results'.")
        results.extend(items)
        next_href = ((data.get("_links") or {}).get("next") or {}).get("href")
        if not next_href or len(items) < page_size:
            break
        page += 1
    return results


def sync_pagos_egresos_desde_siigo(
    idcliente: int,
    deep: bool = False,
    only_missing: bool = True,
    batch_size: int = 50,
    since: Optional[str] = None
) -> str:
    cliente = Cliente.query.filter_by(idcliente=idcliente).first()
    if not cliente:
        raise RuntimeError("Cliente no encontrado")

    cred = SiigoCredencial.query.filter_by(idcliente=idcliente).first()
    if not cred or not cred.client_id or not cred.client_secret or not cred.base_url:
        raise RuntimeError("Credenciales de Siigo no configuradas")

    access_key = dec_local(cred.client_secret)
    if not access_key:
        raise RuntimeError("No se pudo desencriptar el Access Key")

    auth_url = f"{cred.base_url.rstrip('/')}/auth"
    auth_payload = {"username": cred.client_id, "access_key": access_key}
    headers = _headers_json()
    resp = _request_with_retries("POST", auth_url, headers=headers, json=auth_payload)

    if resp.status_code != 200:
        raise RuntimeError(f"Error al autenticar en Siigo (HTTP {resp.status_code}): {resp.text}")

    token = resp.json().get("access_token")
    pagos_list = fetch_all_payment_receipts(cred.base_url, token)

    print(f"🔍 Total pagos recibidos del API: {len(pagos_list)}")

    if since:
        try:
            since_dt = datetime.fromisoformat(since).date()
            pagos_list = [p for p in pagos_list if datetime.fromisoformat(str(p.get("date"))).date() >= since_dt]
        except Exception as e:
            print("⚠️ Error interpretando fecha 'since':", e)

    nuevas, actualizadas, compras_actualizadas = 0, 0, 0

    for it in pagos_list:
        try:
            print("📄 Procesando pago:", it.get("id"), "-", it.get("date"))

            pid = _str(it.get("id"))
            fecha = _str(it.get("date"))
            total = _d(it.get("payment", {}).get("value"))

            # ✅ campos corregidos
            metodo = _str(it.get("payment", {}).get("name"))  
            proveedor_uuid = _str(it.get("supplier", {}).get("id"))  
            prov_id = _str(it.get("supplier", {}).get("identification"))  # NIT / identificación

            items = it.get("items", [])
            print(f"🧾 Facturas asociadas al pago {pid}: {items}")

            aplicada = None
            for item in items:
                due = item.get("due")
                if due:
                    print(f"🔍 Due encontrado: {due}")
                    pref = due.get("prefix")
                    cons = due.get("consecutive")
                    if pref and cons:
                        aplicada = f"{pref}-{cons}"
                        break  # Tomamos solo la primera encontrada

            if not aplicada:
                print(f"❌ No se pudo determinar la factura aplicada para el pago {pid}")

            # buscar si ya existe
            p = SiigoPagoProveedor.query.filter_by(idcliente=idcliente, idpago=pid, factura_aplicada=aplicada).first()
            if not p:
                print("➕ Insertando nuevo pago en la base de datos")
                db.session.add(SiigoPagoProveedor(
                    idcliente=idcliente,
                    idpago=pid,
                    fecha=fecha or None,
                    proveedor_identificacion=prov_id or None,
                    proveedor_nombre=proveedor_uuid or None,
                    metodo_pago=metodo or None,
                    valor=total,
                    factura_aplicada=aplicada or None,
                ))
                nuevas += 1
            else:
                print("🟡 Ya existe pago. Revisando cambios...")
                changed = False
                if fecha and p.fecha != fecha:
                    p.fecha = fecha; changed = True
                if prov_id and (p.proveedor_identificacion or "") != prov_id:
                    p.proveedor_identificacion = prov_id; changed = True
                if proveedor_uuid and (p.proveedor_nombre or "") != proveedor_uuid:
                    p.proveedor_nombre = proveedor_uuid; changed = True
                if metodo and (p.metodo_pago or "") != metodo:
                    p.metodo_pago = metodo; changed = True
                if aplicada and (p.factura_aplicada or "") != aplicada:
                    p.factura_aplicada = aplicada; changed = True
                if p.valor != total:
                    p.valor = total; changed = True
                if changed:
                    print("🛠️ Actualizando pago existente")
                    actualizadas += 1

                # 🔁 Actualizar compras
                if aplicada:
                    compra = SiigoCompra.query.filter_by(idcliente=idcliente, factura_proveedor=aplicada).first()
                    if compra:
                        print(f"🔁 Actualizando estado de compra (factura_proveedor={aplicada})")
                        compra.estado = "pagado"
                        compra.saldo = max(0, float(compra.total or 0) - float(total))
                        compras_actualizadas += 1
                    else:
                        print(f"⚠️ No se encontró compra con factura_proveedor={aplicada}")

        except Exception as e:
            print("❌ Error procesando pago:", it, "\n⛔ Excepción:", e)
            continue

    db.session.commit()
    print(f"✅ Inserciones: {nuevas}, actualizaciones: {actualizadas}, compras actualizadas: {compras_actualizadas}")
    return f"Pagos proveedores: {nuevas} nuevos, {actualizadas} actualizados, total facturas: {len(pagos_list)}. Compras marcadas como pagadas: {compras_actualizadas}."
