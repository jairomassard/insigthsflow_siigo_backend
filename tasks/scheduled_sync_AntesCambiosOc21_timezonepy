import datetime
import psycopg2
from psycopg2.extras import DictCursor
import requests

DB_CONFIG = {
    "dbname": "BD_analisis_siigo",
    "user": "postgres",
    "password": "tu_pass",
    "host": "localhost"
}

API_BASE = "http://localhost:8000"
WINDOW_MINUTES = 30

SYNC_ENDPOINTS = [
    "sync-catalogos",
    "sync-customers",
    "sync-proveedores",
    "sync-productos",
    "sync-facturas",
    "sync-facturas?deep=1&batch=100&only_missing=1",
    "sync-notas-credito",
    "sync-compras",
    "sync-accounts-payable",
    "cross-accounts-payable"
]

def ejecutar_sync(idcliente):
    headers = {"X-ID-CLIENTE": str(idcliente)}
    log_detalle = []
    resultado = "OK"
    for ep in SYNC_ENDPOINTS:
        try:
            res = requests.post(f"{API_BASE}/siigo/{ep}", headers=headers, timeout=600)
            log_detalle.append(f"{ep}: {res.status_code} - {res.text}")
        except Exception as e:
            resultado = "ERROR"
            log_detalle.append(f"{ep}: ERROR - {str(e)}")
            break
    return resultado, "\n".join(log_detalle)

def main():
    now = datetime.datetime.now()
    window_start = (now - datetime.timedelta(minutes=WINDOW_MINUTES)).time()
    window_end = (now + datetime.timedelta(minutes=WINDOW_MINUTES)).time()

    with psycopg2.connect(**DB_CONFIG) as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute("""
                SELECT * FROM siigo_sync_config
                WHERE activo = TRUE
                AND (
                    hora_ejecucion BETWEEN %s AND %s
                )
                AND (
                    ultimo_ejecutado IS NULL OR DATE(ultimo_ejecutado) < CURRENT_DATE
                )
            """, (window_start, window_end))

            for row in cur.fetchall():
                print(f"▶ Ejecutando sync para cliente {row['idcliente']}")
                resultado, detalle = ejecutar_sync(row['idcliente'])

                # Actualizar config
                cur.execute("""
                    UPDATE siigo_sync_config
                    SET ultimo_ejecutado = now(),
                        resultado_ultima_sync = %s,
                        detalle_ultima_sync = %s
                    WHERE id = %s
                """, (resultado, detalle[:5000], row['id']))

                # Insertar en log
                cur.execute("""
                    INSERT INTO siigo_sync_logs (idcliente, fecha_programada, ejecutado_en, resultado, detalle)
                    VALUES (%s, %s, now(), %s, %s)
                """, (row['idcliente'], datetime.datetime.combine(now.date(), row['hora_ejecucion']), resultado, detalle[:5000]))

                conn.commit()

if __name__ == "__main__":
    main()
