from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Optional, Any

class ScanRequest(BaseModel):
    max_results: int = Field(default=25, ge=1, le=100)
    query: Optional[str] = None  # Gmail search query

class ScanItem(BaseModel):
    gmail_message_id: str
    thread_id: str | None = None
    subject: str | None = None
    sender: str | None = None
    date: str | None = None
    threat_level: str
    risk_score: float
    reasons: List[str]
    recommendations: List[str]

class ScanResponse(BaseModel):
    scanned: int
    items: List[ScanItem]
