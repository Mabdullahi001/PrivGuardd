"""
Explainable security module
Provides human-readable explanations for threat detections
"""

from typing import Dict, List
import config
from utils.logger import logger

class SecurityExplainer:
    """Generate explanations for security decisions"""
    
    def __init__(self):
        self.explanation_templates = {
            'safe': "This email appears safe based on our analysis.",
            'suspicious': "This email shows some suspicious characteristics.",
            'malicious': "This email contains clear indicators of malicious intent."
        }
    
    def explain_threat(self, analysis_result: Dict) -> Dict:
        """
        Generate comprehensive explanation for threat analysis
        
        Args:
            analysis_result: Result from ThreatAnalyzer
            
        Returns:
            Dictionary with explanations in different formats
        """
        explanation = {
            'summary': '',
            'technical_details': [],
            'user_friendly': [],
            'risk_factors': [],
            'action_items': []
        }
        
        threat_level = analysis_result.get('threat_level', config.THREAT_SAFE)
        risk_score = analysis_result.get('risk_score', 0.0)
        reasons = analysis_result.get('reasons', [])
        
        # Generate summary
        explanation['summary'] = self._generate_summary(threat_level, risk_score, reasons)
        
        # Technical details
        explanation['technical_details'] = self._generate_technical_details(analysis_result)
        
        # User-friendly explanation
        explanation['user_friendly'] = self._generate_user_friendly(analysis_result)
        
        # Risk factors
        explanation['risk_factors'] = self._extract_risk_factors(analysis_result)
        
        # Action items
        explanation['action_items'] = analysis_result.get('recommendations', [])
        
        return explanation
    
    def _generate_summary(self, threat_level: str, risk_score: float, reasons: List[str]) -> str:
        """Generate summary explanation"""
        if threat_level == config.THREAT_MALICIOUS:
            return f"⚠️ MALICIOUS EMAIL DETECTED (Risk Score: {risk_score:.1%})\n\n" \
                   f"This email has been flagged as malicious due to multiple security concerns. " \
                   f"Do not interact with this email."
        elif threat_level == config.THREAT_SUSPICIOUS:
            return f"⚠️ SUSPICIOUS EMAIL (Risk Score: {risk_score:.1%})\n\n" \
                   f"This email shows suspicious characteristics. Exercise caution before interacting."
        else:
            return f"✅ SAFE EMAIL (Risk Score: {risk_score:.1%})\n\n" \
                   f"This email appears safe based on our security analysis."
    
    def _generate_technical_details(self, analysis_result: Dict) -> List[str]:
        """Generate technical explanation"""
        details = []
        
        # Risk score breakdown
        details.append(f"Overall Risk Score: {analysis_result.get('risk_score', 0.0):.2f}")
        details.append(f"Threat Classification: {analysis_result.get('threat_level', 'Unknown')}")
        
        # Reasons
        reasons = analysis_result.get('reasons', [])
        if reasons:
            details.append("\nDetection Reasons:")
            for i, reason in enumerate(reasons, 1):
                details.append(f"  {i}. {reason}")
        
        # URL analysis
        url_analysis = analysis_result.get('url_analysis', [])
        if url_analysis:
            details.append("\nURL Analysis:")
            for url_result in url_analysis:
                if url_result.get('is_suspicious') or url_result.get('is_malicious'):
                    details.append(f"  - {url_result['url']}: Risk Score {url_result['risk_score']:.2f}")
                    for reason in url_result.get('reasons', []):
                        details.append(f"    • {reason}")
        
        # Attachment analysis
        attach_analysis = analysis_result.get('attachment_analysis', [])
        if attach_analysis:
            details.append("\nAttachment Analysis:")
            for attach_result in attach_analysis:
                if attach_result.get('is_dangerous') or attach_result.get('is_suspicious'):
                    details.append(f"  - {attach_result['filename']}: Risk Score {attach_result['risk_score']:.2f}")
                    for reason in attach_result.get('reasons', []):
                        details.append(f"    • {reason}")
        
        return details
    
    def _generate_user_friendly(self, analysis_result: Dict) -> List[str]:
        """Generate user-friendly explanation"""
        friendly = []
        
        threat_level = analysis_result.get('threat_level', config.THREAT_SAFE)
        
        if threat_level == config.THREAT_MALICIOUS:
            friendly.append("🚫 This email is DANGEROUS")
            friendly.append("")
            friendly.append("Why it's dangerous:")
            reasons = analysis_result.get('reasons', [])
            for reason in reasons[:5]:  # Limit to top 5
                friendly.append(f"  • {reason}")
            friendly.append("")
            friendly.append("What to do:")
            friendly.append("  • Do NOT click any links")
            friendly.append("  • Do NOT download attachments")
            friendly.append("  • Delete this email immediately")
            friendly.append("  • Report as phishing if possible")
        
        elif threat_level == config.THREAT_SUSPICIOUS:
            friendly.append("⚠️ This email looks SUSPICIOUS")
            friendly.append("")
            friendly.append("Why it's suspicious:")
            reasons = analysis_result.get('reasons', [])
            for reason in reasons[:3]:  # Limit to top 3
                friendly.append(f"  • {reason}")
            friendly.append("")
            friendly.append("What to do:")
            friendly.append("  • Verify the sender before clicking links")
            friendly.append("  • Be cautious with attachments")
            friendly.append("  • If unsure, contact sender through another channel")
        
        else:
            friendly.append("✅ This email appears SAFE")
            friendly.append("")
            friendly.append("Our analysis found no major security concerns.")
            friendly.append("However, always remain cautious with emails from unknown senders.")
        
        return friendly
    
    def _extract_risk_factors(self, analysis_result: Dict) -> List[Dict]:
        """Extract and format risk factors"""
        factors = []
        
        # URL risks
        url_analysis = analysis_result.get('url_analysis', [])
        for url_result in url_analysis:
            if url_result.get('is_suspicious') or url_result.get('is_malicious'):
                factors.append({
                    'type': 'URL',
                    'severity': 'Malicious' if url_result.get('is_malicious') else 'Suspicious',
                    'description': f"Suspicious URL detected: {url_result['url']}",
                    'details': url_result.get('reasons', [])
                })
        
        # Attachment risks
        attach_analysis = analysis_result.get('attachment_analysis', [])
        for attach_result in attach_analysis:
            if attach_result.get('is_dangerous') or attach_result.get('is_suspicious'):
                factors.append({
                    'type': 'Attachment',
                    'severity': 'Dangerous' if attach_result.get('is_dangerous') else 'Suspicious',
                    'description': f"Risky attachment: {attach_result['filename']}",
                    'details': attach_result.get('reasons', [])
                })
        
        # General risks
        reasons = analysis_result.get('reasons', [])
        for reason in reasons:
            if 'keyword' in reason.lower() or 'urgent' in reason.lower():
                factors.append({
                    'type': 'Content',
                    'severity': 'Suspicious',
                    'description': reason,
                    'details': []
                })
        
        return factors
    
    def explain_url_risk(self, url_result: Dict) -> str:
        """Generate explanation for URL risk"""
        url = url_result.get('url', 'Unknown')
        risk_score = url_result.get('risk_score', 0.0)
        reasons = url_result.get('reasons', [])
        
        if url_result.get('is_malicious'):
            explanation = f"🚫 MALICIOUS URL: {url}\n\n"
            explanation += f"Risk Score: {risk_score:.1%}\n\n"
            explanation += "Reasons:\n"
            for reason in reasons:
                explanation += f"  • {reason}\n"
            explanation += "\n⚠️ Do NOT click this link!"
        elif url_result.get('is_suspicious'):
            explanation = f"⚠️ SUSPICIOUS URL: {url}\n\n"
            explanation += f"Risk Score: {risk_score:.1%}\n\n"
            explanation += "Reasons:\n"
            for reason in reasons:
                explanation += f"  • {reason}\n"
            explanation += "\n⚠️ Be cautious before clicking."
        else:
            explanation = f"✅ URL appears safe: {url}"
        
        return explanation
    
    def explain_attachment_risk(self, attach_result: Dict) -> str:
        """Generate explanation for attachment risk"""
        filename = attach_result.get('filename', 'Unknown')
        risk_score = attach_result.get('risk_score', 0.0)
        reasons = attach_result.get('reasons', [])
        recommendation = attach_result.get('recommendation', '')
        
        if attach_result.get('is_dangerous'):
            explanation = f"🚫 DANGEROUS ATTACHMENT: {filename}\n\n"
            explanation += f"Risk Score: {risk_score:.1%}\n\n"
            explanation += "Reasons:\n"
            for reason in reasons:
                explanation += f"  • {reason}\n"
            if recommendation:
                explanation += f"\nRecommendation: {recommendation}"
        elif attach_result.get('is_suspicious'):
            explanation = f"⚠️ SUSPICIOUS ATTACHMENT: {filename}\n\n"
            explanation += f"Risk Score: {risk_score:.1%}\n\n"
            explanation += "Reasons:\n"
            for reason in reasons:
                explanation += f"  • {reason}\n"
            if recommendation:
                explanation += f"\nRecommendation: {recommendation}"
        else:
            explanation = f"✅ Attachment appears safe: {filename}"
        
        return explanation
