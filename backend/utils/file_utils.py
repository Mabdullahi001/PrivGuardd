"""
File operations utilities
"""

import os
import hashlib
from pathlib import Path
from typing import Optional
import config

def get_file_hash(file_path: str) -> str:
    """
    Calculate SHA-256 hash of a file
    
    Args:
        file_path: Path to file
        
    Returns:
        Hexadecimal hash string
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def ensure_directory(path: Path) -> Path:
    """
    Ensure directory exists, create if not
    
    Args:
        path: Directory path
        
    Returns:
        Path object
    """
    path.mkdir(parents=True, exist_ok=True)
    return path

def get_file_size(file_path: str) -> int:
    """
    Get file size in bytes
    
    Args:
        file_path: Path to file
        
    Returns:
        File size in bytes
    """
    return os.path.getsize(file_path)

def is_safe_file_type(filename: str) -> bool:
    """
    Check if file extension is considered safe
    
    Args:
        filename: Name of file
        
    Returns:
        True if safe, False otherwise
    """
    safe_extensions = {'.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.gif'}
    ext = Path(filename).suffix.lower()
    return ext in safe_extensions

def get_file_extension(filename: str) -> str:
    """
    Get file extension
    
    Args:
        filename: Name of file
        
    Returns:
        File extension (with dot)
    """
    return Path(filename).suffix.lower()
