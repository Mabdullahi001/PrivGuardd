from __future__ import annotations
import base64
import json
from email.header import decode_header
from typing import Dict, List, Optional
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from privguard_api.settings import settings

def build_gmail_service(token_json: str):
    scopes = [s.strip() for s in settings.GOOGLE_SCOPES.split() if s.strip()]
    info = json.loads(token_json)
    creds = Credentials.from_authorized_user_info(info, scopes=scopes)
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            # Return updated creds JSON so caller can persist refreshed token
            token_json = creds.to_json()
        else:
            raise ValueError("Gmail credentials are invalid; reconnect Gmail.")
    service = build("gmail", "v1", credentials=creds, cache_discovery=False)
    return service, token_json

def get_user_profile(service) -> Dict:
    profile = service.users().getProfile(userId="me").execute()
    return {
        "email": profile.get("emailAddress", ""),
        "messages_total": profile.get("messagesTotal", 0),
        "threads_total": profile.get("threadsTotal", 0),
    }

def list_message_ids(service, max_results: int = 25, query: str | None = None) -> List[Dict]:
    req = service.users().messages().list(userId="me", maxResults=max_results, q=query)
    res = req.execute()
    return res.get("messages", [])

def get_message_details(service, message_id: str) -> Optional[Dict]:
    try:
        message = service.users().messages().get(userId="me", id=message_id, format="full").execute()
        headers = message.get("payload", {}).get("headers", [])

        header_dict: Dict[str, str] = {}
        for h in headers:
            name = (h.get("name") or "").lower()
            value = h.get("value") or ""
            if name:
                header_dict[name] = f"{header_dict[name]} | {value}" if name in header_dict else value

        subject = _get_header(headers, "Subject")
        sender = _get_header(headers, "From")
        date = _get_header(headers, "Date")
        to = _get_header(headers, "To")

        body = _extract_body(message.get("payload", {}))
        attachments = _extract_attachments(message.get("payload", {}))

        return {
            "id": message_id,
            "headers": header_dict,
            "subject": subject,
            "sender": sender,
            "date": date,
            "to": to,
            "body": body,
            "attachments": attachments,
            "snippet": message.get("snippet", ""),
            "thread_id": message.get("threadId", ""),
        }
    except HttpError:
        return None

def _get_header(headers: List[Dict], name: str) -> str:
    for header in headers:
        if (header.get("name") or "").lower() == name.lower():
            value = header.get("value") or ""
            decoded = decode_header(value)
            out = ""
            for part, encoding in decoded:
                if isinstance(part, bytes):
                    out += part.decode(encoding or "utf-8", errors="ignore")
                else:
                    out += part
            return out
    return ""

def _extract_body(payload: Dict) -> str:
    """
    Extract the best-effort body text from Gmail message payload.

    Notes:
    - Gmail payloads can be deeply nested (multipart/alternative, multipart/mixed).
    - Prefer text/plain; if none exists, fall back to text/html (unmodified).
    """
    plain_parts: List[str] = []
    html_parts: List[str] = []

    def walk(part: Dict):
        mime_type = part.get("mimeType", "") or ""
        body_data = part.get("body", {}) or {}

        data = body_data.get("data")
        if data and mime_type in ("text/plain", "text/html"):
            try:
                decoded = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
                if mime_type == "text/plain":
                    plain_parts.append(decoded)
                else:
                    html_parts.append(decoded)
            except Exception:
                pass

        for child in part.get("parts", []) or []:
            walk(child)

    walk(payload)

    if plain_parts:
        return "
".join(plain_parts).strip()
    if html_parts:
        return "
".join(html_parts).strip()
    return ""


def _extract_attachments(payload: Dict) -> List[Dict]:
    """
    Extract attachment metadata (filenames etc.) from payload, recursively.
    This does not download attachment bytes; it provides enough metadata for risk heuristics.
    """
    attachments: List[Dict] = []

    def walk(part: Dict):
        filename = part.get("filename", "") or ""
        body = part.get("body", {}) or {}
        attachment_id = body.get("attachmentId", "")

        if filename and attachment_id:
            attachments.append({
                "filename": filename,
                "mime_type": part.get("mimeType", ""),
                "size": body.get("size", 0),
                "attachment_id": attachment_id,
            })

        for child in part.get("parts", []) or []:
            walk(child)

    walk(payload)
    return attachments
