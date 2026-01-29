"""
AES encryption/decryption engine
"""

import os
import base64
from pathlib import Path
from typing import Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import config
from utils.logger import logger

class CryptoEngine:
    """AES encryption engine for file and data protection"""
    
    def __init__(self):
        self.key_file = config.DATA_DIR / "encryption_key.key"
        self._ensure_key()
    
    def _ensure_key(self):
        """Ensure encryption key exists, create if not"""
        if not os.path.exists(self.key_file):
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            logger.info("Generated new encryption key")
    
    def _load_key(self) -> bytes:
        """Load encryption key from file"""
        with open(self.key_file, 'rb') as f:
            return f.read()
    
    def _get_fernet(self, password: Optional[str] = None) -> Fernet:
        """
        Get Fernet cipher instance
        
        Args:
            password: Optional password for key derivation
            
        Returns:
            Fernet cipher instance
        """
        if password:
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'privguard_salt_2024',
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return Fernet(key)
        else:
            # Use stored key
            key = self._load_key()
            return Fernet(key)
    
    def encrypt_file(self, file_path: str, output_path: Optional[str] = None, 
                    password: Optional[str] = None) -> Tuple[bool, str]:
        """
        Encrypt a file
        
        Args:
            file_path: Path to file to encrypt
            output_path: Optional output path (default: adds .encrypted extension)
            password: Optional password for encryption
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if not os.path.exists(file_path):
                return False, f"File not found: {file_path}"
            
            # Read file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Encrypt
            fernet = self._get_fernet(password)
            encrypted_data = fernet.encrypt(data)
            
            # Determine output path
            if output_path is None:
                output_path = str(Path(file_path).with_suffix('.encrypted'))
            
            # Write encrypted file
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            logger.info(f"Encrypted file: {file_path} -> {output_path}")
            return True, f"File encrypted successfully: {output_path}"
            
        except Exception as e:
            error_msg = f"Encryption failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def decrypt_file(self, encrypted_path: str, output_path: Optional[str] = None,
                    password: Optional[str] = None) -> Tuple[bool, str]:
        """
        Decrypt a file
        
        Args:
            encrypted_path: Path to encrypted file
            output_path: Optional output path (default: removes .encrypted extension)
            password: Optional password for decryption
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if not os.path.exists(encrypted_path):
                return False, f"File not found: {encrypted_path}"
            
            # Read encrypted file
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt
            fernet = self._get_fernet(password)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Determine output path
            if output_path is None:
                if encrypted_path.endswith('.encrypted'):
                    output_path = encrypted_path[:-10]  # Remove .encrypted
                else:
                    output_path = encrypted_path + '.decrypted'
            
            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            logger.info(f"Decrypted file: {encrypted_path} -> {output_path}")
            return True, f"File decrypted successfully: {output_path}"
            
        except Exception as e:
            error_msg = f"Decryption failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def encrypt_text(self, text: str, password: Optional[str] = None) -> str:
        """
        Encrypt text string
        
        Args:
            text: Text to encrypt
            password: Optional password for encryption
            
        Returns:
            Base64 encoded encrypted string
        """
        try:
            fernet = self._get_fernet(password)
            encrypted = fernet.encrypt(text.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Text encryption failed: {str(e)}")
            raise
    
    def decrypt_text(self, encrypted_text: str, password: Optional[str] = None) -> str:
        """
        Decrypt text string
        
        Args:
            encrypted_text: Base64 encoded encrypted text
            password: Optional password for decryption
            
        Returns:
            Decrypted text string
        """
        try:
            fernet = self._get_fernet(password)
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode())
            decrypted = fernet.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Text decryption failed: {str(e)}")
            raise
    
    def generate_key(self) -> bytes:
        """
        Generate a new encryption key
        
        Returns:
            New encryption key bytes
        """
        return Fernet.generate_key()
