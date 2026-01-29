from __future__ import annotations
from cryptography.fernet import Fernet, InvalidToken
from privguard_api.settings import settings

def _get_fernet() -> Fernet:
    if not settings.TOKEN_ENC_KEY:
        # Dev fallback (NOT for production)
        key = Fernet.generate_key()
        return Fernet(key)
    return Fernet(settings.TOKEN_ENC_KEY.encode("utf-8"))

def encrypt_str(plaintext: str) -> str:
    f = _get_fernet()
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")

def decrypt_str(ciphertext: str) -> str:
    f = _get_fernet()
    try:
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as e:
        raise ValueError("Unable to decrypt stored token") from e
