import os

if os.getenv("RAILWAY_ENVIRONMENT_ID") is None:
    from dotenv import load_dotenv
    load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:tu_password@localhost:5432/BD_analisis_siigo"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwtsecretkey")

    # pool_pre_ping: prueba cada conexion con un SELECT liviano antes de
    # usarla y la reemplaza sola si esta muerta - arregla "server closed the
    # connection unexpectedly" (confirmado en vivo 2026-07-19 corriendo
    # sync_completo_desde_alegra_con_log, que intercala llamadas lentas a la
    # API de Alegra con escrituras a la BD - la conexion queda inactiva el
    # tiempo suficiente para que Postgres/un proxy intermedio la cierre).
    # pool_recycle: recicla conexiones de mas de ~4 minutos preventivamente,
    # antes de que lleguen a ese punto.
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
    }

