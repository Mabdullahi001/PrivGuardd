from __future__ import annotations
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from privguard_api.db.session import get_db
from privguard_api.auth.deps import get_current_user
from privguard_api.models import GmailCredential, ScanResult
from privguard_api.schemas.scan import ScanRequest, ScanResponse, ScanItem
from privguard_api.services.gmail_service import build_gmail_service, list_message_ids, get_message_details
from privguard_api.utils.token_vault import decrypt_str, encrypt_str
from core.analyzer import ThreatAnalyzer

router = APIRouter(prefix="/api/scan", tags=["scan"])

@router.post("", response_model=ScanResponse)
def scan(payload: ScanRequest, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    cred = db.query(GmailCredential).filter(GmailCredential.user_id == current_user.id).first()
    if not cred:
        raise HTTPException(status_code=400, detail="Gmail not connected")

    token_json = decrypt_str(cred.token_json_enc)
    service, refreshed_json = build_gmail_service(token_json)

    # Persist refreshed tokens if changed
    if refreshed_json != token_json:
        cred.token_json_enc = encrypt_str(refreshed_json)
        db.commit()

    analyzer = ThreatAnalyzer()

    msg_ids = list_message_ids(service, max_results=payload.max_results, query=payload.query)
    items: list[ScanItem] = []

    for m in msg_ids:
        details = get_message_details(service, m["id"])
        if not details:
            continue
        analysis = analyzer.analyze_email(details)

        result = ScanResult(
            user_id=current_user.id,
            gmail_message_id=details["id"],
            thread_id=details.get("thread_id"),
            subject=details.get("subject"),
            sender=details.get("sender"),
            date=details.get("date"),
            threat_level=analysis.get("threat_level"),
            risk_score=float(analysis.get("risk_score", 0.0)),
            reasons_json=json.dumps(analysis.get("reasons", [])),
            recommendations_json=json.dumps(analysis.get("recommendations", [])),
        )
        db.add(result)

        items.append(ScanItem(
            gmail_message_id=details["id"],
            thread_id=details.get("thread_id"),
            subject=details.get("subject"),
            sender=details.get("sender"),
            date=details.get("date"),
            threat_level=analysis.get("threat_level"),
            risk_score=float(analysis.get("risk_score", 0.0)),
            reasons=analysis.get("reasons", []),
            recommendations=analysis.get("recommendations", []),
        ))

    db.commit()
    return ScanResponse(scanned=len(items), items=items)
