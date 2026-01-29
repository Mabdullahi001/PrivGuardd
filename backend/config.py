"""
PrivGuard Configuration File
Contains app settings, API keys, and constants
"""

import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent

# Credentials directory
CREDENTIALS_DIR = BASE_DIR / "credentials"
CREDENTIALS_FILE = CREDENTIALS_DIR / "credentials.json"
TOKEN_FILE = CREDENTIALS_DIR / "token.json"

# Data directories
DATA_DIR = BASE_DIR / "data"
DATASETS_DIR = DATA_DIR / "datasets"
MODELS_DIR = DATA_DIR / "models"
LOGS_DIR = DATA_DIR / "logs"
SAMPLES_DIR = DATA_DIR / "samples"

# Gmail API Settings
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
GMAIL_API_VERSION = 'v1'

# Threat Classification Labels
THREAT_SAFE = "Safe"
THREAT_SUSPICIOUS = "Suspicious"
THREAT_MALICIOUS = "Malicious"

# Detection Thresholds
SUSPICIOUS_THRESHOLD = 0.5
MALICIOUS_THRESHOLD = 0.8

# Phishing Indicators
PHISHING_KEYWORDS = [
    'verify', 'suspend', 'login', 'urgent', 'immediately',
    'account', 'security', 'click here', 'update now',
    'confirm', 'validate', 'expired', 'limited time'
]

# Suspicious URL Patterns
SUSPICIOUS_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
    'short.link', 'rebrand.ly'
]

# Encryption Settings
ENCRYPTION_ALGORITHM = 'AES'
KEY_SIZE = 32  # 256 bits

# UI Settings
UI_THEME = "dark"
UI_COLOR_SCHEME = "blue"
WINDOW_WIDTH = 1200
WINDOW_HEIGHT = 800

# Logging
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Create directories if they don't exist
for directory in [CREDENTIALS_DIR, DATA_DIR, DATASETS_DIR, MODELS_DIR, LOGS_DIR, SAMPLES_DIR]:
    directory.mkdir(parents=True, exist_ok=True)
