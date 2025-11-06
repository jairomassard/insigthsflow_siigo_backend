# 📄 Archivo: cron_sync.py
import os
import pytz
from datetime import datetime, timedelta
from app import app, db
from models import Cliente, SiigoSyncConfig

# === CONFIGURACIÓN DEL CRON ===
# Ejecuta cada 4 horas (configuras esto en Railway)
# Este script se encarga de decidir qué clientes sincronizar.

def ejecutar_sync_pendientes():
    with app.app_context():
        print("🕓 Iniciando verificación de sincronizaciones automáticas...")
        now_utc = datetime.utcnow().replace(tzinfo=pytz.utc)

        # Traer todos los clientes activos con configuración
        configs = SiigoSyncConfig.query.all()
        print(f"🔍 Se encontraron {len(configs)} configuraciones registradas.")

        for cfg in configs:
            cliente = Cliente.query.get(cfg.idcliente)
            if not cliente or not cfg.activo:
                continue

            tz_str = cliente.timezone or "America/Bogota"
            tz = pytz.timezone(tz_str)
            now_local = now_utc.astimezone(tz)

            # Calcular próxima ejecución esperada
            ultima_ejec = cfg.ultimo_ejecutado.astimezone(tz) if cfg.ultimo_ejecutado else None
            proxima_ejec = None
            if ultima_ejec:
                proxima_ejec = ultima_ejec + timedelta(days=cfg.frecuencia_dias)
                proxima_ejec = proxima_ejec.replace(
                    hour=cfg.hora_ejecucion.hour,
                    minute=cfg.hora_ejecucion.minute,
                    second=cfg.hora_ejecucion.second
                )
            else:
                # Si nunca ha ejecutado, usar la hora programada del día actual
                proxima_ejec = now_local.replace(
                    hour=cfg.hora_ejecucion.hour,
                    minute=cfg.hora_ejecucion.minute,
                    second=cfg.hora_ejecucion.second
                )

            # Verificar si ya toca ejecutar
            if now_local >= proxima_ejec:
                print(f"⏰ Ejecutando sincronización para cliente {cliente.id} ({cliente.nombre})")
                try:
                    with app.test_client() as client:
                        resp = client.post(
                            "/siigo/sync-all",
                            headers={"X-ID-CLIENTE": str(cliente.id)},
                            json={"origen": "cron"}
                        )
                        print(f"✅ Resultado cliente {cliente.id}: {resp.status_code}")
                except Exception as e:
                    print(f"❌ Error ejecutando sync para cliente {cliente.id}: {e}")
            else:
                faltan = (proxima_ejec - now_local).total_seconds() / 3600
                print(f"🕒 Cliente {cliente.id} aún no debe ejecutar (faltan {faltan:.1f}h)")

        print("🏁 Verificación de sincronizaciones finalizada.")

if __name__ == "__main__":
    ejecutar_sync_pendientes()
