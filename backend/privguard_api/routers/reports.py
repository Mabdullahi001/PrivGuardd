from __future__ import annotations
import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from privguard_api.db.session import get_db
from privguard_api.auth.deps import get_current_user
from privguard_api.models import ScanResult
from privguard_api.schemas.scan import ScanItem

router = APIRouter(prefix="/api/reports", tags=["reports"])

@router.get("/latest", response_model=list[ScanItem])
def latest(limit: int = 50, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    rows = (
        db.query(ScanResult)
        .filter(ScanResult.user_id == current_user.id)
        .order_by(desc(ScanResult.created_at))
        .limit(min(max(limit, 1), 200))
        .all()
    )
    out: list[ScanItem] = []
    for r in rows:
        out.append(ScanItem(
            gmail_message_id=r.gmail_message_id,
            thread_id=r.thread_id,
            subject=r.subject,
            sender=r.sender,
            date=r.date,
            threat_level=r.threat_level,
            risk_score=r.risk_score,
            reasons=json.loads(r.reasons_json),
            recommendations=json.loads(r.recommendations_json),
        ))
    return out
