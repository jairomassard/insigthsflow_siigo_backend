import psycopg2
import pandas as pd

# Configuración de la conexión (ajusta a tu entorno)
DB_CONFIG = {
    "dbname": "BD_analisis_siigo",
    "user": "postgres",
    "password": "J3r0n1m0",
    "host": "localhost",
    "port": 5432,
}

# Consulta: todas las facturas de septiembre 2025 con detalles clave
SQL = """
SELECT
    f.idfactura,
    f.fecha,
    f.cliente_nombre,
    f.subtotal,
    f.impuestos_total,
    f.total,
    f.saldo,
    f.estado_pago,
    f.retenciones,
    f.observaciones
FROM facturas_enriquecidas f
WHERE f.fecha BETWEEN '2025-09-01' AND '2025-09-30'
ORDER BY f.fecha, f.idfactura;
"""

def main():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        df = pd.read_sql(SQL, conn)
        conn.close()

        print("📊 Facturas septiembre 2025 descargadas:", len(df))
        print(df.head())

        # Guardar a CSV para que lo revisemos aparte
        df.to_csv("facturas_sep2025.csv", index=False, encoding="utf-8-sig")
        print("✅ Archivo generado: facturas_sep2025.csv")

    except Exception as e:
        print("❌ Error:", e)

if __name__ == "__main__":
    main()
