from __future__ import annotations
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from privguard_api.settings import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)

def create_access_token(subject: str, user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRES_MINUTES)
    payload = {"sub": subject, "uid": user_id, "exp": expire}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[ALGORITHM])
    except JWTError as e:
        raise ValueError("Invalid token") from e


def create_oauth_state(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(minutes=10)
    payload = {"pur": "gmail_oauth", "uid": user_id, "exp": expire}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)

def decode_oauth_state(state: str) -> int:
    try:
        payload = jwt.decode(state, settings.JWT_SECRET, algorithms=[ALGORITHM])
        if payload.get("pur") != "gmail_oauth":
            raise ValueError("Invalid state purpose")
        return int(payload.get("uid"))
    except Exception as e:
        raise ValueError("Invalid or expired state") from e
