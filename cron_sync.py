# 📄 Archivo: cron_sync.py
import pytz
from datetime import datetime, timedelta
from app import app, db
from models import Cliente, SiigoSyncConfig
from models_alegra import AlegraSyncConfig, AlegraSyncLog
from alegra.alegra_sync_all import sync_completo_desde_alegra_con_log


# === CONFIGURACIÓN DEL CRON ===
# Railway despierta este script según el Cron Schedule configurado.
#
# Recomendación:
# - Si quieres respetar horas programadas por cliente, configura Railway cada 1 hora:
#   0 * * * *
# - Si lo dejas cada 4 horas:
#   0 */4 * * *
#   puede ejecutar con retraso, según la ventana en la que caiga.
#
# Este script:
# - Recorre clientes activos.
# - Evalúa hora local de cada cliente.
# - Ejecuta sync-all solo si:
#   1) Ya llegó o pasó la hora programada de hoy.
#   2) No se ha ejecutado automáticamente hoy.
#   3) Se cumple frecuencia_dias respecto a ultimo_auto_ejecutado.
#
# IMPORTANTE:
# - Las ejecuciones manuales NO bloquean este cron.
# - Para decidir ejecución automática se usa ultimo_auto_ejecutado, no ultimo_ejecutado.


def _localizar_fecha_hora(tz, fecha_local, hora):
    """
    Construye un datetime timezone-aware para la fecha local + hora configurada.
    """
    naive = datetime.combine(fecha_local, hora)
    return tz.localize(naive)


def _ya_ejecuto_auto_hoy(cfg, tz, now_local):
    """
    Retorna True si ultimo_auto_ejecutado fue hoy según zona horaria del cliente.
    """
    if not cfg.ultimo_auto_ejecutado:
        return False

    ultimo_auto_local = cfg.ultimo_auto_ejecutado.astimezone(tz)
    return ultimo_auto_local.date() == now_local.date()


def _cumple_frecuencia(cfg, tz, now_local):
    """
    Valida frecuencia_dias usando ultimo_auto_ejecutado.
    Si no hay ultima auto, puede ejecutar.
    """
    if not cfg.ultimo_auto_ejecutado:
        return True

    frecuencia = int(cfg.frecuencia_dias or 1)
    if frecuencia <= 1:
        return True

    ultimo_auto_local = cfg.ultimo_auto_ejecutado.astimezone(tz)
    dias_desde_ultima_auto = (now_local.date() - ultimo_auto_local.date()).days

    return dias_desde_ultima_auto >= frecuencia


def ejecutar_sync_pendientes():
    with app.app_context():
        print("\n" + "=" * 70)
        print("🕓 INICIO DE VERIFICACIÓN AUTOMÁTICA DE SINCRONIZACIONES")
        print("=" * 70)

        now_utc = datetime.utcnow().replace(tzinfo=pytz.utc)
        configs = SiigoSyncConfig.query.filter_by(activo=True).all()

        print(f"🕓 Hora UTC actual: {now_utc.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        print(f"🔍 Configuraciones activas encontradas: {len(configs)}\n")

        total_ok = 0
        total_error = 0
        total_pendientes = 0
        total_omitidos_hoy = 0
        total_omitidos_frecuencia = 0

        for cfg in configs:
            cliente = Cliente.query.get(cfg.idcliente)

            if not cliente:
                print(f"⚠️ Config id={cfg.id} omitida: cliente {cfg.idcliente} no existe.")
                continue

            if not cfg.hora_ejecucion:
                print(f"⚠️ Cliente {cliente.idcliente} omitido: no tiene hora_ejecucion.")
                total_pendientes += 1
                continue

            tz_str = cliente.timezone or "America/Bogota"
            tz = pytz.timezone(tz_str)
            now_local = now_utc.astimezone(tz)

            hora_programada_hoy = _localizar_fecha_hora(
                tz=tz,
                fecha_local=now_local.date(),
                hora=cfg.hora_ejecucion
            )

            ya_paso_hora = now_local >= hora_programada_hoy
            ya_auto_hoy = _ya_ejecuto_auto_hoy(cfg, tz, now_local)
            cumple_frecuencia = _cumple_frecuencia(cfg, tz, now_local)

            ultimo_auto_local = (
                cfg.ultimo_auto_ejecutado.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
                if cfg.ultimo_auto_ejecutado else None
            )

            ultimo_general_local = (
                cfg.ultimo_ejecutado.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
                if cfg.ultimo_ejecutado else None
            )

            print(f"👤 Cliente {cliente.idcliente} - {cliente.nombre}")
            print(f"   🌎 Zona horaria: {tz_str}")
            print(f"   🕐 Hora local actual: {now_local.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   ⏰ Hora programada hoy: {hora_programada_hoy.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   📌 Última sync general: {ultimo_general_local or 'Nunca'}")
            print(f"   🤖 Última sync automática: {ultimo_auto_local or 'Nunca'}")
            print(f"   📅 Frecuencia días: {cfg.frecuencia_dias}")
            print(f"   📄 DS fecha desde: {cfg.ds_fecha_desde.isoformat() if cfg.ds_fecha_desde else 'SIN LÍMITE'}")

            if not ya_paso_hora:
                faltan_horas = (hora_programada_hoy - now_local).total_seconds() / 3600
                print(f"   💤 No ejecuta: aún no llega la hora programada. Faltan {faltan_horas:.2f} horas.")
                total_pendientes += 1
                print("-" * 70)
                continue

            if ya_auto_hoy:
                print("   ⏸ No ejecuta: ya tuvo sincronización automática hoy.")
                total_omitidos_hoy += 1
                print("-" * 70)
                continue

            if not cumple_frecuencia:
                print("   ⏸ No ejecuta: no cumple frecuencia_dias según ultima sync automática.")
                total_omitidos_frecuencia += 1
                print("-" * 70)
                continue

            print("   🚀 Ejecutando sincronización automática vía /siigo/sync-all ...")

            try:
                with app.test_client() as client:
                    resp = client.post(
                        "/siigo/sync-all",
                        headers={"X-ID-CLIENTE": str(cliente.idcliente)},
                        json={"origen": "cron"}
                    )

                    body = resp.get_data(as_text=True)

                    if resp.status_code < 400:
                        print(f"   ✅ Sincronización automática completada. HTTP {resp.status_code}")
                        total_ok += 1
                    else:
                        print(f"   ❌ Error HTTP {resp.status_code} durante sync-all.")
                        print(f"   Detalle: {body[:1000]}")
                        total_error += 1

            except Exception as e:
                print(f"   💥 Excepción ejecutando sync-all: {e}")
                total_error += 1

            print("-" * 70)

        print("\n📊 RESUMEN DEL CRON")
        print("=" * 70)
        print(f"✅ Éxitos automáticos          : {total_ok}")
        print(f"❌ Errores                    : {total_error}")
        print(f"⏳ Pendientes por hora         : {total_pendientes}")
        print(f"⏸ Omitidos porque ya corrieron: {total_omitidos_hoy}")
        print(f"📅 Omitidos por frecuencia     : {total_omitidos_frecuencia}")
        print("=" * 70)
        print("🏁 Verificación de sincronizaciones finalizada.\n")


def ejecutar_sync_pendientes_alegra():
    """Mismo mecanismo que ejecutar_sync_pendientes(), pero para clientes
    Alegra (AlegraSyncConfig).

    IMPORTANTE (bug real encontrado y corregido probando esto en vivo,
    2026-07-19): NO llama a /alegra/sync-all por HTTP/test_client como hace
    la version Siigo. Ese endpoint lanza el trabajo real en un hilo daemon
    para sobrevivir al timeout de un proxy/gateway cuando lo dispara un clic
    manual del navegador - pero cron_sync.py es un proceso de corta duracion
    que termina apenas acaba este script, asi que un hilo daemon lanzado
    desde aqui muere a mitad de camino en cuanto el proceso termina,
    dejando la sincronizacion huerfana en EN_EJECUCION para siempre
    (confirmado con una corrida real antes de este fix). Por eso aqui se
    llama sync_completo_desde_alegra_con_log(idcliente) DIRECTO y sincrono -
    no hay restriccion de timeout de proxy que respetar en un script cron,
    asi que simplemente se espera a que termine."""
    with app.app_context():
        print("\n" + "=" * 70)
        print("🕓 INICIO DE VERIFICACIÓN AUTOMÁTICA DE SINCRONIZACIONES (ALEGRA)")
        print("=" * 70)

        now_utc = datetime.utcnow().replace(tzinfo=pytz.utc)
        configs = AlegraSyncConfig.query.filter_by(activo=True).all()

        print(f"🕓 Hora UTC actual: {now_utc.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        print(f"🔍 Configuraciones activas encontradas: {len(configs)}\n")

        total_ok = 0
        total_error = 0
        total_pendientes = 0
        total_omitidos_hoy = 0
        total_omitidos_frecuencia = 0

        for cfg in configs:
            cliente = Cliente.query.get(cfg.idcliente)

            if not cliente:
                print(f"⚠️ Config id={cfg.id} omitida: cliente {cfg.idcliente} no existe.")
                continue

            if not cfg.hora_ejecucion:
                print(f"⚠️ Cliente {cliente.idcliente} omitido: no tiene hora_ejecucion.")
                total_pendientes += 1
                continue

            tz_str = cliente.timezone or "America/Bogota"
            tz = pytz.timezone(tz_str)
            now_local = now_utc.astimezone(tz)

            hora_programada_hoy = _localizar_fecha_hora(
                tz=tz,
                fecha_local=now_local.date(),
                hora=cfg.hora_ejecucion
            )

            ya_paso_hora = now_local >= hora_programada_hoy
            ya_auto_hoy = _ya_ejecuto_auto_hoy(cfg, tz, now_local)
            cumple_frecuencia = _cumple_frecuencia(cfg, tz, now_local)

            print(f"👤 Cliente {cliente.idcliente} - {cliente.nombre}")
            print(f"   🌎 Zona horaria: {tz_str}")
            print(f"   🕐 Hora local actual: {now_local.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   ⏰ Hora programada hoy: {hora_programada_hoy.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   📅 Frecuencia días: {cfg.frecuencia_dias}")

            if not ya_paso_hora:
                faltan_horas = (hora_programada_hoy - now_local).total_seconds() / 3600
                print(f"   💤 No ejecuta: aún no llega la hora programada. Faltan {faltan_horas:.2f} horas.")
                total_pendientes += 1
                print("-" * 70)
                continue

            if ya_auto_hoy:
                print("   ⏸ No ejecuta: ya tuvo sincronización automática hoy.")
                total_omitidos_hoy += 1
                print("-" * 70)
                continue

            if not cumple_frecuencia:
                print("   ⏸ No ejecuta: no cumple frecuencia_dias según ultima sync automática.")
                total_omitidos_frecuencia += 1
                print("-" * 70)
                continue

            # No permitir dos sincronizaciones en paralelo (mismo chequeo que
            # hace /alegra/sync-all).
            en_curso = AlegraSyncLog.query.filter_by(
                idcliente=cliente.idcliente, resultado="EN_EJECUCION"
            ).first()
            if en_curso:
                print("   ⏸ Ya había una sincronización en curso para este cliente, se omite.")
                total_omitidos_hoy += 1
                print("-" * 70)
                continue

            # IMPORTANTE: se llama la funcion de sync DIRECTO (sincrono),
            # NO via /alegra/sync-all por HTTP/test_client. Ese endpoint
            # lanza el trabajo real en un hilo daemon para sobrevivir al
            # timeout de un proxy/gateway en el caso de un clic manual desde
            # el navegador - pero cron_sync.py es un proceso de corta
            # duracion (termina apenas acaba este script), asi que un hilo
            # daemon lanzado aqui moriria a mitad de camino en cuanto el
            # proceso termine, dejando la sincronizacion huerfana a medias
            # (confirmado con una prueba real: quedo en EN_EJECUCION para
            # siempre). Sin restriccion de tiempo de proxy que respetar aqui,
            # lo correcto es simplemente esperar a que termine.
            print("   🚀 Ejecutando sincronización automática (síncrono) ...")

            logrec = AlegraSyncLog(
                idcliente=cliente.idcliente,
                fecha_programada=now_local,
                ejecutado_en=None,
                resultado="EN_EJECUCION",
                detalle="Sincronización en curso (cron)...",
                origen="cron",
                total_pasos=0,
                pasos_ok=0,
                pasos_error=0,
            )
            db.session.add(logrec)
            db.session.commit()

            try:
                resumen = sync_completo_desde_alegra_con_log(cliente.idcliente)
            except Exception as e:
                resumen = {
                    "resultado": "ERROR",
                    "detalle": f"Excepción no controlada: {e}",
                    "total_pasos": 0,
                    "pasos_ok": 0,
                    "pasos_error": 1,
                    "endpoint_fallido": "sync-all",
                }

            logrec.resultado = resumen["resultado"]
            logrec.detalle = resumen["detalle"][:10000]
            logrec.total_pasos = resumen["total_pasos"]
            logrec.pasos_ok = resumen["pasos_ok"]
            logrec.pasos_error = resumen["pasos_error"]
            logrec.endpoint_fallido = resumen["endpoint_fallido"]
            logrec.ejecutado_en = datetime.utcnow()
            db.session.commit()

            ahora_utc_fin = datetime.utcnow()
            cfg.ultimo_ejecutado = ahora_utc_fin
            cfg.ultimo_auto_ejecutado = ahora_utc_fin
            cfg.resultado_ultima_sync = resumen["resultado"]
            cfg.detalle_ultima_sync = resumen["detalle"][:2000]
            db.session.commit()

            if resumen["resultado"] == "ERROR":
                print(f"   ❌ Sincronización terminó con error: {resumen['detalle'][:300]}")
                total_error += 1
            else:
                print(f"   ✅ Sincronización completada. Pasos OK: {resumen['pasos_ok']}, errores: {resumen['pasos_error']}")
                total_ok += 1

            print("-" * 70)

        print("\n📊 RESUMEN DEL CRON (ALEGRA)")
        print("=" * 70)
        print(f"✅ Encolados correctamente     : {total_ok}")
        print(f"❌ Errores                    : {total_error}")
        print(f"⏳ Pendientes por hora         : {total_pendientes}")
        print(f"⏸ Omitidos porque ya corrieron: {total_omitidos_hoy}")
        print(f"📅 Omitidos por frecuencia     : {total_omitidos_frecuencia}")
        print("=" * 70)
        print("🏁 Verificación de sincronizaciones Alegra finalizada.\n")


if __name__ == "__main__":
    ejecutar_sync_pendientes()
    ejecutar_sync_pendientes_alegra()