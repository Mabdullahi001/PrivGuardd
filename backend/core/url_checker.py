"""
URL phishing detection module
"""

import re
from typing import List, Dict
from urllib.parse import urlparse
import config
from utils.text_utils import extract_urls
from utils.security_utils import is_suspicious_domain
from utils.logger import logger

class URLChecker:
    """Check URLs for phishing indicators"""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'bit\.ly',
            r'tinyurl\.com',
            r'goo\.gl',
            r't\.co',
            r'short\.link',
            r'rebrand\.ly'
        ]
    
    def check_url(self, url: str) -> Dict:
        """
        Analyze a single URL for phishing indicators
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with analysis results
        """
        result = {
            'url': url,
            'is_suspicious': False,
            'is_malicious': False,
            'reasons': [],
            'risk_score': 0.0
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for suspicious domains
            if is_suspicious_domain(domain):
                result['is_suspicious'] = True
                result['risk_score'] += 0.4
                result['reasons'].append(f"URL uses suspicious shortening service: {domain}")
            
            # Check for IP addresses (often suspicious)
            if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                result['is_suspicious'] = True
                result['risk_score'] += 0.3
                result['reasons'].append("URL uses IP address instead of domain name")
            
            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    result['is_suspicious'] = True
                    result['risk_score'] += 0.2
                    result['reasons'].append(f"URL matches suspicious pattern: {pattern}")
            
            # Check for mixed case (potential homograph attack)
            if domain != domain.lower() and domain != domain.upper():
                result['risk_score'] += 0.1
                result['reasons'].append("URL uses mixed case (potential homograph attack)")
            
            # Check URL length (very long URLs can be suspicious)
            if len(url) > 100:
                result['risk_score'] += 0.1
                result['reasons'].append("URL is unusually long")
            
            # Determine if malicious
            if result['risk_score'] >= 0.7:
                result['is_malicious'] = True
            
            elif result['risk_score'] >= 0.4:
                result['is_suspicious'] = True
            
        except Exception as e:
            logger.error(f"Error checking URL {url}: {str(e)}")
            result['reasons'].append("Error analyzing URL")
        
        return result
    
    def check_urls_in_text(self, text: str) -> List[Dict]:
        """
        Extract and check all URLs in text
        
        Args:
            text: Text to analyze
            
        Returns:
            List of URL analysis results
        """
        urls = extract_urls(text)
        results = []
        
        for url in urls:
            result = self.check_url(url)
            results.append(result)
        
        return results
    
    def get_risk_summary(self, url_results: List[Dict]) -> Dict:
        """
        Get summary of URL risks
        
        Args:
            url_results: List of URL check results
            
        Returns:
            Summary dictionary
        """
        if not url_results:
            return {
                'total_urls': 0,
                'suspicious_count': 0,
                'malicious_count': 0,
                'max_risk_score': 0.0
            }
        
        suspicious = sum(1 for r in url_results if r['is_suspicious'])
        malicious = sum(1 for r in url_results if r['is_malicious'])
        max_risk = max((r['risk_score'] for r in url_results), default=0.0)
        
        return {
            'total_urls': len(url_results),
            'suspicious_count': suspicious,
            'malicious_count': malicious,
            'max_risk_score': max_risk
        }
