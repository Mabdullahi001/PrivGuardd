from __future__ import annotations
from pydantic import BaseModel

class GmailStatusResponse(BaseModel):
    connected: bool
    connected_email: str | None = None
    scopes: str | None = None
