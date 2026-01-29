"""
Text processing and NLP utilities
"""

import re
from typing import List, Set
import config

# NLTK imports with fallback
try:
    import nltk
    from nltk.corpus import stopwords
    from nltk.tokenize import word_tokenize
    
    # Download NLTK data if not present
    try:
        nltk.data.find('tokenizers/punkt')
    except LookupError:
        try:
            nltk.download('punkt', quiet=True)
        except:
            pass
    
    try:
        stopwords.words('english')
    except LookupError:
        try:
            nltk.download('stopwords', quiet=True)
        except:
            pass
    
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False
    # Fallback functions if NLTK is not available
    def word_tokenize(text):
        return text.split()
    
    class StopwordsFallback:
        def words(self, lang):
            return ['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by']
    
    stopwords = StopwordsFallback()

def extract_urls(text: str) -> List[str]:
    """
    Extract all URLs from text
    
    Args:
        text: Input text
        
    Returns:
        List of URLs found
    """
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    return urls

def extract_emails(text: str) -> List[str]:
    """
    Extract email addresses from text
    
    Args:
        text: Input text
        
    Returns:
        List of email addresses found
    """
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    return emails

def clean_text(text: str) -> str:
    """
    Clean and normalize text
    
    Args:
        text: Input text
        
    Returns:
        Cleaned text
    """
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    # Remove special characters but keep basic punctuation
    text = re.sub(r'[^\w\s\.\,\!\?]', '', text)
    return text.strip()

def tokenize_text(text: str) -> List[str]:
    """
    Tokenize text into words
    
    Args:
        text: Input text
        
    Returns:
        List of tokens
    """
    try:
        if NLTK_AVAILABLE:
            tokens = word_tokenize(text.lower())
            return tokens
        else:
            return text.lower().split()
    except:
        return text.lower().split()

def remove_stopwords(tokens: List[str]) -> List[str]:
    """
    Remove stopwords from token list
    
    Args:
        tokens: List of word tokens
        
    Returns:
        Tokens without stopwords
    """
    try:
        if NLTK_AVAILABLE:
            stop_words = set(stopwords.words('english'))
        else:
            stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        return [token for token in tokens if token not in stop_words]
    except:
        return tokens

def count_phishing_keywords(text: str) -> int:
    """
    Count occurrences of phishing keywords
    
    Args:
        text: Input text
        
    Returns:
        Count of phishing keywords found
    """
    text_lower = text.lower()
    count = sum(1 for keyword in config.PHISHING_KEYWORDS if keyword in text_lower)
    return count

def has_urgent_language(text: str) -> bool:
    """
    Check if text contains urgent language
    
    Args:
        text: Input text
        
    Returns:
        True if urgent language detected
    """
    urgent_words = ['urgent', 'immediately', 'asap', 'now', 'expired', 'limited time']
    text_lower = text.lower()
    return any(word in text_lower for word in urgent_words)
