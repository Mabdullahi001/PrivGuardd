from __future__ import annotations
from pydantic import BaseModel
from typing import Any, List, Optional

class AttachmentItem(BaseModel):
    filename: str
    mime_type: Optional[str] = None
    size: Optional[int] = None
    attachment_id: Optional[str] = None

class MessageDetail(BaseModel):
    gmail_message_id: str
    thread_id: Optional[str] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    to: Optional[str] = None
    date: Optional[str] = None
    snippet: Optional[str] = None
    body: Optional[str] = None
    attachments: List[AttachmentItem] = []

class MessageDetailResponse(BaseModel):
    message: MessageDetail
    analysis: dict[str, Any]
