from __future__ import annotations
from urllib.parse import urlencode
from google_auth_oauthlib.flow import Flow
from privguard_api.settings import settings

def build_flow() -> Flow:
    scopes = [s.strip() for s in settings.GOOGLE_SCOPES.split() if s.strip()]
    flow = Flow.from_client_secrets_file(
        settings.GOOGLE_CLIENT_SECRETS_FILE,
        scopes=scopes,
    )
    flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
    return flow

def get_authorization_url(state: str | None = None) -> tuple[str, str]:
    flow = build_flow()
    auth_url, state_out = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        state=state,
    )
    return auth_url, state_out

def exchange_code(code: str) -> str:
    flow = build_flow()
    flow.fetch_token(code=code)
    creds = flow.credentials
    return creds.to_json()
