from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from privguard_api.db.session import get_db
from privguard_api.auth.deps import get_current_user
from privguard_api.models import GmailCredential
from privguard_api.services.gmail_service import build_gmail_service, get_message_details
from privguard_api.utils.token_vault import decrypt_str, encrypt_str
from privguard_api.schemas.messages import MessageDetailResponse, MessageDetail, AttachmentItem
from core.analyzer import ThreatAnalyzer

router = APIRouter(prefix="/api/messages", tags=["messages"])

@router.get("/{message_id}", response_model=MessageDetailResponse)
def get_message(message_id: str, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    cred = db.query(GmailCredential).filter(GmailCredential.user_id == current_user.id).first()
    if not cred:
        raise HTTPException(status_code=400, detail="Gmail not connected")

    token_json = decrypt_str(cred.token_json_enc)
    service, refreshed_json = build_gmail_service(token_json)

    # Persist refreshed token if needed
    if refreshed_json != token_json:
        cred.token_json_enc = encrypt_str(refreshed_json)
        db.commit()

    details = get_message_details(service, message_id)
    if not details:
        raise HTTPException(status_code=404, detail="Message not found")

    analyzer = ThreatAnalyzer()
    analysis = analyzer.analyze_email(details)

    msg = MessageDetail(
        gmail_message_id=details["id"],
        thread_id=details.get("thread_id"),
        subject=details.get("subject"),
        sender=details.get("sender"),
        to=details.get("to"),
        date=details.get("date"),
        snippet=details.get("snippet"),
        body=details.get("body"),
        attachments=[AttachmentItem(**a) for a in (details.get("attachments") or [])],
    )
    return MessageDetailResponse(message=msg, analysis=analysis)
