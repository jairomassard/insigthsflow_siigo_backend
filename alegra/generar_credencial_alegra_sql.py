"""
Utilidad de una sola vez: cifra un email+token de Alegra con la misma llave
Fernet (APP_CRYPTO_KEY) que usa la app en produccion, y genera el INSERT SQL
listo para pegar en la sesion de psql contra Railway.

No requiere Flask ni SQLAlchemy - solo lee APP_CRYPTO_KEY de backend/.env y
usa 'cryptography' directamente, para poder correr suelto sin levantar la app.

Uso (correr TU, no por Claude, para que el token nunca pase por el chat):
    cd backend
    python alegra/generar_credencial_alegra_sql.py
"""

import getpass
import os

from cryptography.fernet import Fernet


def _leer_env(nombre_var: str, ruta_env: str = ".env") -> str | None:
    if not os.path.exists(ruta_env):
        return None
    with open(ruta_env, "r", encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            if linea.startswith(f"{nombre_var}="):
                return linea.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def main():
    crypto_key = os.environ.get("APP_CRYPTO_KEY") or _leer_env("APP_CRYPTO_KEY")
    if not crypto_key:
        print("No se encontro APP_CRYPTO_KEY (ni en el entorno ni en backend/.env).")
        print("Debe ser la MISMA llave que usa la app en Railway, o el token cifrado")
        print("no se podra desencriptar en produccion.")
        return

    fernet = Fernet(crypto_key.encode() if isinstance(crypto_key, str) else crypto_key)

    idcliente = input("idcliente (el que vas a usar para la prueba Alegra): ").strip()
    email = input("Email de Alegra (usuario Basic Auth): ").strip()
    token = getpass.getpass("Token de API de Alegra (no se muestra en pantalla): ").strip()

    if not (idcliente and email and token):
        print("Faltan datos, no se genero nada.")
        return

    token_cifrado = fernet.encrypt(token.encode())
    token_hex = token_cifrado.hex()

    print("\n--- Pega esto en tu sesion de psql contra Railway ---\n")
    print(f"INSERT INTO fuente_datos_cliente (idcliente, proveedor, activo, fecha_conexion)")
    print(f"VALUES ({idcliente}, 'alegra', TRUE, NOW())")
    print(f"ON CONFLICT (idcliente) DO UPDATE SET proveedor = 'alegra', activo = TRUE;\n")

    print(f"INSERT INTO alegra_credenciales (idcliente, email, token)")
    print(f"VALUES ({idcliente}, '{email}', E'\\\\x{token_hex}')")
    print(f"ON CONFLICT (idcliente) DO UPDATE SET email = EXCLUDED.email, token = EXCLUDED.token, updated_at = NOW();\n")


if __name__ == "__main__":
    main()
