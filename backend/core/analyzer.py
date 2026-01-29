"""
Main threat detection analyzer
Combines all detection modules
"""

from typing import Dict, List
import config
from core.url_checker import URLChecker
from core.attachment_scanner import AttachmentScanner
from core.header_analyzer import HeaderAnalyzer
from utils.text_utils import (
    count_phishing_keywords, has_urgent_language,
    extract_urls, extract_emails
)
from utils.logger import logger

class ThreatAnalyzer:
    """Main threat detection engine"""
    
    def __init__(self):
        self.url_checker = URLChecker()
        self.attachment_scanner = AttachmentScanner()
        self.header_analyzer = HeaderAnalyzer()
    
    def analyze_email(self, email_data: Dict) -> Dict:
        """
        Analyze email for threats
        
        Args:
            email_data: Dictionary with email information
            
        Returns:
            Dictionary with threat analysis results
        """
        result = {
            'email_id': email_data.get('id', ''),
            'subject': email_data.get('subject', ''),
            'sender': email_data.get('sender', ''),
            'threat_level': config.THREAT_SAFE,
            'risk_score': 0.0,
            'reasons': [],
            'url_analysis': [],
            'attachment_analysis': [],
            'header_analysis': {},
            'recommendations': []
        }
        
        try:
            # Combine subject and body for analysis
            text = f"{email_data.get('subject', '')} {email_data.get('body', '')}"
            body = email_data.get('body', '')
            
            # 1. Check for phishing keywords
            keyword_count = count_phishing_keywords(text)
            if keyword_count > 0:
                result['risk_score'] += keyword_count * 0.1
                result['reasons'].append(f"Email contains {keyword_count} phishing-related keywords")
            
            # 2. Check for urgent language
            if has_urgent_language(text):
                result['risk_score'] += 0.2
                result['reasons'].append("Email contains urgent language")
            
            # 3. Analyze URLs
            urls = extract_urls(body)
            if urls:
                url_results = self.url_checker.check_urls_in_text(body)
                result['url_analysis'] = url_results
                
                url_summary = self.url_checker.get_risk_summary(url_results)
                if url_summary['malicious_count'] > 0:
                    result['risk_score'] += 0.4
                    result['reasons'].append(f"Email contains {url_summary['malicious_count']} malicious URL(s)")
                elif url_summary['suspicious_count'] > 0:
                    result['risk_score'] += 0.2
                    result['reasons'].append(f"Email contains {url_summary['suspicious_count']} suspicious URL(s)")
            
            # 4. Analyze attachments
            attachments = email_data.get('attachments', [])
            if attachments:
                attachment_results = self.attachment_scanner.scan_attachments(attachments)
                result['attachment_analysis'] = attachment_results
                
                attach_summary = self.attachment_scanner.get_risk_summary(attachment_results)
                if attach_summary['dangerous_count'] > 0:
                    result['risk_score'] += 0.5
                    result['reasons'].append(f"Email contains {attach_summary['dangerous_count']} dangerous attachment(s)")
                elif attach_summary['suspicious_count'] > 0:
                    result['risk_score'] += 0.2
                    result['reasons'].append(f"Email contains {attach_summary['suspicious_count']} suspicious attachment(s)")
            
            # 5. Analyze headers
            headers = email_data.get('headers', {}) or {}
            if headers:
                header_result = self.header_analyzer.analyze(headers)
                result['header_analysis'] = header_result
                if header_result.get("issues"):
                    result['reasons'].extend(header_result.get("issues", []))
                header_risk = float(header_result.get("risk_score", 0.0))
                if header_risk > 0:
                    result['risk_score'] += header_risk

            # 6. Check sender domain (basic check)
            sender = email_data.get('sender', '')
            if '@' in sender:
                sender_domain = sender.split('@')[1].lower()
                # Check if sender domain matches common patterns
                if any(domain in sender_domain for domain in config.SUSPICIOUS_DOMAINS):
                    result['risk_score'] += 0.1
                    result['reasons'].append("Sender domain appears suspicious")
            
            # 7. Determine threat level
            if result['risk_score'] >= config.MALICIOUS_THRESHOLD:
                result['threat_level'] = config.THREAT_MALICIOUS
                result['recommendations'].append("Do not interact with this email")
                result['recommendations'].append("Delete this email immediately")
                result['recommendations'].append("Report as phishing if possible")
            elif result['risk_score'] >= config.SUSPICIOUS_THRESHOLD:
                result['threat_level'] = config.THREAT_SUSPICIOUS
                result['recommendations'].append("Be cautious with this email")
                result['recommendations'].append("Verify sender before clicking links")
                result['recommendations'].append("Do not download attachments unless verified")
            else:
                result['threat_level'] = config.THREAT_SAFE
                result['recommendations'].append("Email appears safe")
            
            # Cap risk score at 1.0
            result['risk_score'] = min(result['risk_score'], 1.0)
            
            logger.info(f"Analyzed email {result['email_id']}: {result['threat_level']} (score: {result['risk_score']:.2f})")
            
        except Exception as e:
            logger.error(f"Error analyzing email: {str(e)}")
            result['reasons'].append(f"Error during analysis: {str(e)}")
        
        return result
    
    def analyze_batch(self, emails: List[Dict]) -> List[Dict]:
        """
        Analyze multiple emails
        
        Args:
            emails: List of email dictionaries
            
        Returns:
            List of analysis results
        """
        results = []
        for email in emails:
            result = self.analyze_email(email)
            results.append(result)
        return results
