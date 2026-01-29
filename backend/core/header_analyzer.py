"""
Email header analysis module
Provides simple heuristic checks on common headers
"""

from typing import Dict, List
from utils.logger import logger


class HeaderAnalyzer:
    """Analyze email headers for suspicious patterns"""

    def analyze(self, headers: Dict[str, str]) -> Dict:
        """
        Analyze headers dictionary for risk indicators.

        Args:
            headers: Dict of header-name (lowercase) to value

        Returns:
            Dict with header_analysis, including:
              - issues: list of strings
              - risk_score: float
        """
        result = {
            "issues": [],
            "risk_score": 0.0,
        }

        try:
            from_header = headers.get("from", "")
            reply_to = headers.get("reply-to", "")
            return_path = headers.get("return-path", "")
            auth_results = headers.get("authentication-results", "")

            # 1. From vs Reply-To mismatch
            if from_header and reply_to:
                from_domain = _extract_domain(from_header)
                reply_domain = _extract_domain(reply_to)
                if from_domain and reply_domain and from_domain != reply_domain:
                    result["risk_score"] += 0.2
                    result["issues"].append(
                        f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})"
                    )

            # 2. From vs Return-Path mismatch
            if from_header and return_path:
                from_domain = _extract_domain(from_header)
                rp_domain = _extract_domain(return_path)
                if from_domain and rp_domain and from_domain != rp_domain:
                    result["risk_score"] += 0.2
                    result["issues"].append(
                        f"Return-Path domain ({rp_domain}) differs from From domain ({from_domain})"
                    )

            # 3. SPF / authentication results
            if auth_results:
                lower = auth_results.lower()
                if "spf=fail" in lower or "spf=softfail" in lower:
                    result["risk_score"] += 0.3
                    result["issues"].append("SPF authentication failed or soft-failed")
                if "dkim=fail" in lower:
                    result["risk_score"] += 0.3
                    result["issues"].append("DKIM authentication failed")

        except Exception as e:
            logger.error(f"Error analyzing headers: {str(e)}")
            result["issues"].append(f"Error analyzing headers: {str(e)}")

        return result


def _extract_domain(value: str) -> str:
    """
    Extract domain from an email-like header value.
    Handles forms like 'Name <user@example.com>'
    """
    if "<" in value and ">" in value:
        inside = value.split("<", 1)[1].split(">", 1)[0]
        value = inside
    if "@" in value:
        return value.split("@")[-1].strip().lower()
    return ""

