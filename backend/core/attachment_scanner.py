"""
Attachment scanning and analysis module
"""

from typing import List, Dict
import config
from utils.file_utils import get_file_extension, is_safe_file_type
from utils.logger import logger

class AttachmentScanner:
    """Scan email attachments for security risks"""
    
    def __init__(self):
        self.dangerous_extensions = {
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs',
            '.js', '.jar', '.msi', '.dll', '.app', '.deb', '.rpm'
        }
        
        self.suspicious_extensions = {
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
        }
    
    def scan_attachment(self, attachment: Dict) -> Dict:
        """
        Scan a single attachment for risks
        
        Args:
            attachment: Attachment dictionary with filename, mime_type, etc.
            
        Returns:
            Dictionary with scan results
        """
        result = {
            'filename': attachment.get('filename', 'unknown'),
            'mime_type': attachment.get('mime_type', ''),
            'size': attachment.get('size', 0),
            'is_dangerous': False,
            'is_suspicious': False,
            'reasons': [],
            'risk_score': 0.0,
            'recommendation': ''
        }
        
        filename = result['filename']
        ext = get_file_extension(filename)
        
        # Check for dangerous extensions
        if ext in self.dangerous_extensions:
            result['is_dangerous'] = True
            result['risk_score'] = 1.0
            result['reasons'].append(f"File has dangerous extension: {ext}")
            result['recommendation'] = "Do not open this file. It may contain malware."
        
        # Check for suspicious extensions
        elif ext in self.suspicious_extensions:
            result['is_suspicious'] = True
            result['risk_score'] = 0.5
            result['reasons'].append(f"File has suspicious extension: {ext}")
            result['recommendation'] = "Scan this file with antivirus before opening."
        
        # Check file size (very large files can be suspicious)
        if result['size'] > 10 * 1024 * 1024:  # 10MB
            result['risk_score'] += 0.2
            result['reasons'].append("File is unusually large")
        
        # Check for double extensions (e.g., file.pdf.exe)
        if filename.count('.') > 1:
            parts = filename.split('.')
            if len(parts) >= 2:
                last_ext = '.' + parts[-1]
                second_last = '.' + parts[-2]
                if last_ext in self.dangerous_extensions:
                    result['is_dangerous'] = True
                    result['risk_score'] = 1.0
                    result['reasons'].append("File uses double extension to hide dangerous type")
                    result['recommendation'] = "This is a common malware technique. Do not open."
        
        # Safe file check
        if is_safe_file_type(filename) and not result['is_dangerous']:
            result['recommendation'] = "File appears safe, but always verify sender."
        
        return result
    
    def scan_attachments(self, attachments: List[Dict]) -> List[Dict]:
        """
        Scan multiple attachments
        
        Args:
            attachments: List of attachment dictionaries
            
        Returns:
            List of scan results
        """
        results = []
        for attachment in attachments:
            result = self.scan_attachment(attachment)
            results.append(result)
        return results
    
    def get_risk_summary(self, scan_results: List[Dict]) -> Dict:
        """
        Get summary of attachment risks
        
        Args:
            scan_results: List of attachment scan results
            
        Returns:
            Summary dictionary
        """
        if not scan_results:
            return {
                'total_attachments': 0,
                'dangerous_count': 0,
                'suspicious_count': 0,
                'max_risk_score': 0.0
            }
        
        dangerous = sum(1 for r in scan_results if r['is_dangerous'])
        suspicious = sum(1 for r in scan_results if r['is_suspicious'])
        max_risk = max((r['risk_score'] for r in scan_results), default=0.0)
        
        return {
            'total_attachments': len(scan_results),
            'dangerous_count': dangerous,
            'suspicious_count': suspicious,
            'max_risk_score': max_risk
        }
