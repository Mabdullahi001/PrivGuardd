"""
Gmail API client for PrivGuard
Handles OAuth authentication and email retrieval
"""

import os
import base64
import json
from email import message_from_string
from email.header import decode_header
from typing import List, Dict, Optional
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import config
from utils.logger import logger

class GmailClient:
    """Gmail API client for reading emails"""
    
    def __init__(self):
        self.service = None
        self.creds = None
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate with Gmail API using OAuth 2.0"""
        try:
            # Check if token exists
            if os.path.exists(config.TOKEN_FILE):
                self.creds = Credentials.from_authorized_user_file(
                    str(config.TOKEN_FILE), config.SCOPES
                )
            
            # If no valid credentials, get new ones
            if not self.creds or not self.creds.valid:
                if self.creds and self.creds.expired and self.creds.refresh_token:
                    self.creds.refresh(Request())
                else:
                    if not os.path.exists(config.CREDENTIALS_FILE):
                        raise FileNotFoundError(
                            f"Credentials file not found at {config.CREDENTIALS_FILE}. "
                            "Please download credentials.json from Google Cloud Console."
                        )
                    
                    flow = InstalledAppFlow.from_client_secrets_file(
                        str(config.CREDENTIALS_FILE), config.SCOPES
                    )
                    self.creds = flow.run_local_server(port=0)
                
                # Save credentials for next run
                with open(config.TOKEN_FILE, 'w') as token:
                    token.write(self.creds.to_json())
            
            # Build Gmail service
            self.service = build('gmail', config.GMAIL_API_VERSION, credentials=self.creds)
            logger.info("Gmail authentication successful")
            
        except Exception as e:
            logger.error(f"Gmail authentication failed: {str(e)}")
            raise
    
    def get_messages(self, max_results: int = 50, query: str = None) -> List[Dict]:
        """
        Retrieve email messages from inbox
        
        Args:
            max_results: Maximum number of messages to retrieve
            query: Gmail query string (e.g., 'is:unread')
            
        Returns:
            List of message dictionaries
        """
        try:
            if query:
                results = self.service.users().messages().list(
                    userId='me', maxResults=max_results, q=query
                ).execute()
            else:
                results = self.service.users().messages().list(
                    userId='me', maxResults=max_results
                ).execute()
            
            messages = results.get('messages', [])
            email_list = []
            
            for msg in messages:
                email_data = self.get_message_details(msg['id'])
                if email_data:
                    email_list.append(email_data)
            
            logger.info(f"Retrieved {len(email_list)} messages")
            return email_list
            
        except HttpError as e:
            logger.error(f"Error retrieving messages: {str(e)}")
            return []
    
    def get_message_details(self, message_id: str) -> Optional[Dict]:
        """
        Get detailed information about a specific message
        
        Args:
            message_id: Gmail message ID
            
        Returns:
            Dictionary with message details or None
        """
        try:
            message = self.service.users().messages().get(
                userId='me', id=message_id, format='full'
            ).execute()
            
            headers = message['payload'].get('headers', [])

            # Build simple header dict (lowercase keys) for analyzers
            header_dict = {}
            for h in headers:
                name = h.get("name", "").lower()
                value = h.get("value", "")
                if name:
                    # For repeated headers (like Received), keep concatenated values
                    if name in header_dict:
                        header_dict[name] = header_dict[name] + " | " + value
                    else:
                        header_dict[name] = value
            
            # Extract headers
            subject = self._get_header(headers, 'Subject')
            sender = self._get_header(headers, 'From')
            date = self._get_header(headers, 'Date')
            to = self._get_header(headers, 'To')
            
            # Extract body
            body = self._extract_body(message['payload'])
            
            # Extract attachments info
            attachments = self._extract_attachments(message['payload'])
            
            return {
                'id': message_id,
                'headers': header_dict,
                'subject': subject,
                'sender': sender,
                'date': date,
                'to': to,
                'body': body,
                'attachments': attachments,
                'snippet': message.get('snippet', ''),
                'thread_id': message.get('threadId', '')
            }
            
        except HttpError as e:
            logger.error(f"Error retrieving message {message_id}: {str(e)}")
            return None
    
    def _get_header(self, headers: List[Dict], name: str) -> str:
        """Extract header value by name"""
        for header in headers:
            if header['name'].lower() == name.lower():
                value = header['value']
                # Decode encoded headers
                decoded = decode_header(value)
                decoded_str = ''
                for part, encoding in decoded:
                    if isinstance(part, bytes):
                        decoded_str += part.decode(encoding or 'utf-8', errors='ignore')
                    else:
                        decoded_str += part
                return decoded_str
        return ''
    
    def _extract_body(self, payload: Dict) -> str:
        """Extract email body from payload"""
        body = ''
        
        if 'parts' in payload:
            for part in payload['parts']:
                mime_type = part.get('mimeType', '')
                if mime_type == 'text/plain':
                    data = part.get('body', {}).get('data', '')
                    if data:
                        body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                elif mime_type == 'text/html' and not body:
                    data = part.get('body', {}).get('data', '')
                    if data:
                        body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        else:
            mime_type = payload.get('mimeType', '')
            if mime_type in ['text/plain', 'text/html']:
                data = payload.get('body', {}).get('data', '')
                if data:
                    body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        
        return body
    
    def _extract_attachments(self, payload: Dict) -> List[Dict]:
        """Extract attachment information"""
        attachments = []
        
        if 'parts' in payload:
            for part in payload['parts']:
                filename = part.get('filename', '')
                if filename:
                    attachments.append({
                        'filename': filename,
                        'mime_type': part.get('mimeType', ''),
                        'size': part.get('body', {}).get('size', 0),
                        'attachment_id': part.get('body', {}).get('attachmentId', '')
                    })
        
        return attachments
    
    def get_user_profile(self) -> Dict:
        """Get Gmail user profile information"""
        try:
            profile = self.service.users().getProfile(userId='me').execute()
            return {
                'email': profile.get('emailAddress', ''),
                'messages_total': profile.get('messagesTotal', 0),
                'threads_total': profile.get('threadsTotal', 0)
            }
        except HttpError as e:
            logger.error(f"Error retrieving profile: {str(e)}")
            return {}
