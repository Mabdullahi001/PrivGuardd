from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from privguard_api.db.session import get_db
from privguard_api.auth.deps import get_current_user
from privguard_api.auth.security import create_oauth_state, decode_oauth_state
from privguard_api.models import GmailCredential, User
from privguard_api.schemas.gmail import GmailStatusResponse
from privguard_api.services.gmail_oauth import get_authorization_url, exchange_code
from privguard_api.services.gmail_service import build_gmail_service, get_user_profile
from privguard_api.settings import settings
from privguard_api.utils.token_vault import encrypt_str

router = APIRouter(prefix="/api/gmail", tags=["gmail"])

@router.get("/oauth/start")
def oauth_start(current_user=Depends(get_current_user)):
    state = create_oauth_state(current_user.id)
    auth_url, _state = get_authorization_url(state=state)
    return {"auth_url": auth_url}

@router.get("/oauth/callback")
def oauth_callback(code: str, state: str, db: Session = Depends(get_db)):
    # Identify which PrivGuard user initiated OAuth
    try:
        user_id = decode_oauth_state(state)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="Unknown user")

    token_json = exchange_code(code)

    # Resolve connected email for display
    service, refreshed = build_gmail_service(token_json)
    profile = get_user_profile(service)
    connected_email = profile.get("email")

    cred = db.query(GmailCredential).filter(GmailCredential.user_id == user.id).first()
    if not cred:
        cred = GmailCredential(
            user_id=user.id,
            token_json_enc=encrypt_str(refreshed),
            scopes=settings.GOOGLE_SCOPES,
            connected_email=connected_email,
        )
        db.add(cred)
    else:
        cred.token_json_enc = encrypt_str(refreshed)
        cred.scopes = settings.GOOGLE_SCOPES
        cred.connected_email = connected_email
    db.commit()

    return RedirectResponse(url=f"{settings.FRONTEND_URL}/dashboard?gmail=connected")

@router.get("/status", response_model=GmailStatusResponse)
def status(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    cred = db.query(GmailCredential).filter(GmailCredential.user_id == current_user.id).first()
    if not cred:
        return GmailStatusResponse(connected=False)
    return GmailStatusResponse(connected=True, connected_email=cred.connected_email, scopes=cred.scopes)

@router.post("/disconnect")
def disconnect(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    cred = db.query(GmailCredential).filter(GmailCredential.user_id == current_user.id).first()
    if cred:
        db.delete(cred)
        db.commit()
    return {"disconnected": True}
