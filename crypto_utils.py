# crypto_utils.py
import os
from cryptography.fernet import Fernet, InvalidToken

FERNET_KEY = os.environ.get("APP_CRYPTO_KEY")
fernet = Fernet(FERNET_KEY) if FERNET_KEY else None

def dec(b: bytes | None) -> str | None:
    if b is None:
        return None
    if not fernet:
        return b.decode()
    try:
        return fernet.decrypt(b).decode()
    except InvalidToken:
        return None
