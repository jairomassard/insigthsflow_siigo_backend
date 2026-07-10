"""
Orquestador: corre el sync completo de Alegra para un cliente, en el orden
correcto de dependencias (catalogos -> movimientos -> documentos que
referencian terceros/vendedores/productos por FK blanda).
"""

import os
import sys

# Debe cargarse ANTES que cualquier import que toque crypto_utils/config (ver
# nota igual en alegra_sync_catalogos.py) - este archivo es el que primero
# dispara la cadena de imports de los demas modulos alegra_sync_*.
from dotenv import load_dotenv
load_dotenv()

from alegra.alegra_sync_catalogos import (
    sync_catalogos_desde_alegra,
    sync_categorias_desde_alegra,
    sync_terceros_desde_alegra,
    sync_vendedores_desde_alegra,
    sync_centros_costo_desde_alegra,
    sync_retenciones_catalogo_desde_alegra,
    sync_impuestos_catalogo_desde_alegra,
    sync_productos_desde_alegra,
)
from alegra.alegra_sync_movimientos import sync_movimientos_desde_alegra
from alegra.alegra_sync_facturas import sync_facturas_desde_alegra
from alegra.alegra_sync_notas_credito import sync_notas_credito_desde_alegra
from alegra.alegra_sync_compras import sync_compras_desde_alegra
from alegra.alegra_sync_pagos import sync_pagos_desde_alegra
from alegra.alegra_transform_contable import transform_auxiliar_contable_desde_alegra


def sync_completo_desde_alegra(idcliente: int) -> list[str]:
    resultados = list(sync_catalogos_desde_alegra(idcliente))
    resultados.append(sync_movimientos_desde_alegra(idcliente))
    resultados.append(sync_facturas_desde_alegra(idcliente))
    resultados.append(sync_notas_credito_desde_alegra(idcliente))
    resultados.append(sync_compras_desde_alegra(idcliente))
    resultados.append(sync_pagos_desde_alegra(idcliente))
    # Antes habia que correr esto a mano (script aparte) despues de cada
    # sync - encontrado 2026-07-10 probando con un segundo cliente real
    # (Maslux LED) que nunca quedo conectado al flujo automatico. A
    # diferencia de Siigo (donde el auxiliar contable se carga por Excel
    # manual), en Alegra el dato sale de /journals via la API, asi que este
    # paso final SI puede (y debe) ser automatico.
    resultados.append(transform_auxiliar_contable_desde_alegra(idcliente))
    return resultados


def sync_completo_desde_alegra_con_log(idcliente: int) -> dict:
    """Variante para el endpoint HTTP: corre cada paso con su propio
    try/except (un catalogo o proceso que falle no bota el resto ni pierde
    el registro de lo que si funciono), pensada para poblar AlegraSyncLog y
    dar un historial de sincronizaciones como el que ya existe para Siigo.
    """
    from models import db

    pasos = [
        ("categorias", lambda: sync_categorias_desde_alegra(idcliente)),
        ("terceros", lambda: sync_terceros_desde_alegra(idcliente)),
        ("vendedores", lambda: sync_vendedores_desde_alegra(idcliente)),
        ("centros_costo", lambda: sync_centros_costo_desde_alegra(idcliente)),
        ("retenciones_catalogo", lambda: sync_retenciones_catalogo_desde_alegra(idcliente)),
        ("impuestos_catalogo", lambda: sync_impuestos_catalogo_desde_alegra(idcliente)),
        ("productos", lambda: sync_productos_desde_alegra(idcliente)),
        ("movimientos", lambda: sync_movimientos_desde_alegra(idcliente)),
        ("facturas", lambda: sync_facturas_desde_alegra(idcliente)),
        ("notas_credito", lambda: sync_notas_credito_desde_alegra(idcliente)),
        ("compras", lambda: sync_compras_desde_alegra(idcliente)),
        ("pagos", lambda: sync_pagos_desde_alegra(idcliente)),
        ("auxiliar_contable", lambda: transform_auxiliar_contable_desde_alegra(idcliente)),
    ]

    log_parts = []
    pasos_ok = 0
    pasos_error = 0
    endpoint_fallido = None

    for nombre, fn in pasos:
        try:
            mensaje = fn()
            log_parts.append(f"{nombre} -> OK: {mensaje}")
            pasos_ok += 1
        except Exception as e:
            db.session.rollback()
            log_parts.append(f"{nombre} -> ERROR: {e}")
            pasos_error += 1
            if not endpoint_fallido:
                endpoint_fallido = nombre

    resultado = "OK" if pasos_error == 0 else "ERROR"

    return {
        "resultado": resultado,
        "detalle": "\n".join(log_parts),
        "total_pasos": len(pasos),
        "pasos_ok": pasos_ok,
        "pasos_error": pasos_error,
        "endpoint_fallido": endpoint_fallido,
    }


if __name__ == "__main__":
    try:
        from app import app
    except Exception:
        print("No se pudo importar 'app' desde app.py.")
        sys.exit(1)

    cid = None
    if len(sys.argv) >= 2 and sys.argv[1].isdigit():
        cid = int(sys.argv[1])
    else:
        env_id = os.getenv("IDCLIENTE")
        if env_id and env_id.isdigit():
            cid = int(env_id)

    if not cid:
        print("Falta idcliente. Usa argumento numerico o variable de entorno IDCLIENTE.")
        sys.exit(1)

    with app.app_context():
        for linea in sync_completo_desde_alegra(cid):
            print(linea)
