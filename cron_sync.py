# 📄 Archivo: cron_sync.py
import os
import pytz
from datetime import datetime, timedelta
from app import app, db
from models import Cliente, SiigoSyncConfig

# === CONFIGURACIÓN DEL CRON ===
# Ejecuta cada 4 horas (definido en Railway)
# Este script recorre todos los clientes activos y dispara su sincronización si corresponde.

def ejecutar_sync_pendientes():
    with app.app_context():
        print("\n" + "=" * 60)
        print("🕓 INICIO DE VERIFICACIÓN AUTOMÁTICA DE SINCRONIZACIONES")
        print("=" * 60)

        now_utc = datetime.utcnow().replace(tzinfo=pytz.utc)
        configs = SiigoSyncConfig.query.all()

        print(f"🔍 Se encontraron {len(configs)} configuraciones registradas.\n")

        total_ok = 0
        total_error = 0
        total_pendientes = 0

        for cfg in configs:
            cliente = Cliente.query.get(cfg.idcliente)
            if not cliente or not cfg.activo:
                continue

            tz_str = cliente.timezone or "America/Bogota"
            tz = pytz.timezone(tz_str)
            now_local = now_utc.astimezone(tz)

            # Calcular próxima ejecución esperada
            ultima_ejec = cfg.ultimo_ejecutado.astimezone(tz) if cfg.ultimo_ejecutado else None
            if ultima_ejec:
                proxima_ejec = ultima_ejec + timedelta(days=cfg.frecuencia_dias)
                proxima_ejec = proxima_ejec.replace(
                    hour=cfg.hora_ejecucion.hour,
                    minute=cfg.hora_ejecucion.minute,
                    second=cfg.hora_ejecucion.second
                )
            else:
                proxima_ejec = now_local.replace(
                    hour=cfg.hora_ejecucion.hour,
                    minute=cfg.hora_ejecucion.minute,
                    second=cfg.hora_ejecucion.second
                )

            print(f"👤 Cliente {cliente.idcliente} – {cliente.nombre}")
            print(f"   🕐 Hora local: {now_local.strftime('%Y-%m-%d %H:%M:%S')} ({tz_str})")
            print(f"   📅 Próxima ejecución esperada: {proxima_ejec.strftime('%Y-%m-%d %H:%M:%S')}")

            if now_local >= proxima_ejec:
                print(f"   ⏰ Ejecutando sincronización automática...")
                try:
                    with app.test_client() as client:
                        resp = client.post(
                            "/siigo/sync-all",
                            headers={"X-ID-CLIENTE": str(cliente.idcliente)},
                            json={"origen": "cron"}
                        )
                        if resp.status_code < 400:
                            print(f"   ✅ Sincronización completada con éxito (HTTP {resp.status_code})")
                            total_ok += 1
                        else:
                            print(f"   ❌ Error HTTP {resp.status_code} durante la sincronización")
                            total_error += 1
                except Exception as e:
                    print(f"   💥 Excepción: {e}")
                    total_error += 1
            else:
                faltan = (proxima_ejec - now_local).total_seconds() / 3600
                print(f"   💤 No ejecuta aún (faltan {faltan:.1f} horas)")
                total_pendientes += 1

            print("-" * 60)

        # === Resumen final ===
        print("\n📊 RESUMEN DEL CRON")
        print("=" * 60)
        print(f"✅ Éxitos     : {total_ok}")
        print(f"❌ Errores    : {total_error}")
        print(f"⏳ Pendientes : {total_pendientes}")
        print("=" * 60)
        print("🏁 Verificación de sincronizaciones finalizada.\n")

if __name__ == "__main__":
    ejecutar_sync_pendientes()
