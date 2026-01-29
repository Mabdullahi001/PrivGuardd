"""
Security utilities and validation functions
"""

import re
import hashlib
from typing import Optional
import config

def validate_email(email: str) -> bool:
    """
    Validate email format
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid format
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def hash_password(password: str) -> str:
    """
    Hash password using SHA-256
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password
    """
    return hashlib.sha256(password.encode()).hexdigest()

def check_password_strength(password: str) -> dict:
    """
    Analyze password strength
    
    Args:
        password: Password to check
        
    Returns:
        Dictionary with strength analysis
    """
    strength = {
        'score': 0,
        'feedback': [],
        'is_strong': False
    }
    
    if len(password) >= 8:
        strength['score'] += 1
    else:
        strength['feedback'].append("Password should be at least 8 characters")
    
    if re.search(r'[a-z]', password):
        strength['score'] += 1
    else:
        strength['feedback'].append("Add lowercase letters")
    
    if re.search(r'[A-Z]', password):
        strength['score'] += 1
    else:
        strength['feedback'].append("Add uppercase letters")
    
    if re.search(r'[0-9]', password):
        strength['score'] += 1
    else:
        strength['feedback'].append("Add numbers")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        strength['score'] += 1
    else:
        strength['feedback'].append("Add special characters")
    
    strength['is_strong'] = strength['score'] >= 4
    
    return strength

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove path components
    filename = filename.replace('..', '').replace('/', '').replace('\\', '')
    # Remove dangerous characters
    filename = re.sub(r'[<>:"|?*]', '', filename)
    return filename

def is_suspicious_domain(domain: str) -> bool:
    """
    Check if domain is in suspicious domains list
    
    Args:
        domain: Domain to check
        
    Returns:
        True if suspicious
    """
    domain_lower = domain.lower()
    return any(susp_domain in domain_lower for susp_domain in config.SUSPICIOUS_DOMAINS)
