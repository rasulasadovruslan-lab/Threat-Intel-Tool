"""Auth for your own endpoint. Constant-time compare prevents timing attacks."""
import secrets

from fastapi import Header, HTTPException

from .config import get_settings


async def require_token(x_api_token: str = Header(default="")) -> None:
    expected = get_settings().app_token.get_secret_value()
    if not secrets.compare_digest(x_api_token.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing token")
