"""JWT 认证：签发与校验访问令牌。"""
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.core.config import settings

bearer_scheme = HTTPBearer(auto_error=False)


def create_token(user_id: int, username: str) -> str:
    payload = {
        "sub": str(user_id),
        "username": username,
        "exp": datetime.utcnow() + timedelta(minutes=settings.token_ttl_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


def get_current_user(cred: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if cred is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "缺少认证信息")
    try:
        payload = decode_token(cred.credentials)
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "令牌无效或已过期")
    return {"id": int(payload["sub"]), "username": payload["username"]}
