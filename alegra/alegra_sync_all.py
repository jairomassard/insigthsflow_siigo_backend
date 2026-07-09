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

from alegra.alegra_sync_catalogos import sync_catalogos_desde_alegra
from alegra.alegra_sync_movimientos import sync_movimientos_desde_alegra
from alegra.alegra_sync_facturas import sync_facturas_desde_alegra
from alegra.alegra_sync_notas_credito import sync_notas_credito_desde_alegra
from alegra.alegra_sync_compras import sync_compras_desde_alegra
from alegra.alegra_sync_pagos import sync_pagos_desde_alegra


def sync_completo_desde_alegra(idcliente: int) -> list[str]:
    resultados = list(sync_catalogos_desde_alegra(idcliente))
    resultados.append(sync_movimientos_desde_alegra(idcliente))
    resultados.append(sync_facturas_desde_alegra(idcliente))
    resultados.append(sync_notas_credito_desde_alegra(idcliente))
    resultados.append(sync_compras_desde_alegra(idcliente))
    resultados.append(sync_pagos_desde_alegra(idcliente))
    return resultados


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
