"""
LocalSafe - Security Utilities Module

This module provides utility functions for secure operations including
memory management, file hashing, and secure random generation.
"""

import os
import hashlib
import secrets
from typing import Optional
from pathlib import Path


class SecureBytes:
    """Wrapper for sensitive byte data with secure cleanup."""
    
    def __init__(self, data: bytes):
        self._data = bytearray(data)
        self._cleared = False
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()
    
    @property
    def data(self) -> bytes:
        if self._cleared:
            raise RuntimeError("SecureBytes has been cleared")
        return bytes(self._data)
    
    def clear(self) -> None:
        """Securely clear the data from memory."""
        if not self._cleared:
            # Overwrite with random data multiple times
            for _ in range(3):
                for i in range(len(self._data)):
                    self._data[i] = secrets.randbits(8)
            self._data.clear()
            self._cleared = True
    
    def __del__(self):
        self.clear()


def generate_salt(length: int = 32) -> bytes:
    """Generate a cryptographically secure random salt.
    
    Args:
        length: Length of salt in bytes (default: 32)
        
    Returns:
        Cryptographically secure random bytes
    """
    return secrets.token_bytes(length)


def generate_key(length: int = 32) -> bytes:
    """Generate a cryptographically secure random key.
    
    Args:
        length: Length of key in bytes (default: 32 for AES-256)
        
    Returns:
        Cryptographically secure random key
    """
    return secrets.token_bytes(length)


def generate_nonce(length: int = 12) -> bytes:
    """Generate a cryptographically secure random nonce for AES-GCM.
    
    Args:
        length: Length of nonce in bytes (default: 12 for GCM)
        
    Returns:
        Cryptographically secure random nonce
    """
    return secrets.token_bytes(length)


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA-256 hash of a file for integrity verification.
    
    Args:
        file_path: Path to the file to hash
        
    Returns:
        Hexadecimal SHA-256 hash of the file
        
    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read
    """
    sha256_hash = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        # Read file in chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    
    return sha256_hash.hexdigest()


def compute_data_hash(data: bytes) -> str:
    """Compute SHA-256 hash of byte data.
    
    Args:
        data: Byte data to hash
        
    Returns:
        Hexadecimal SHA-256 hash of the data
    """
    return hashlib.sha256(data).hexdigest()


def secure_delete_file(file_path: Path) -> bool:
    """Attempt to securely delete a file by overwriting before deletion.
    
    Args:
        file_path: Path to file to securely delete
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if not file_path.exists():
            return True
            
        # Get file size
        file_size = file_path.stat().st_size
        
        # Overwrite file with random data multiple times
        with open(file_path, 'r+b') as f:
            for _ in range(3):  # 3 passes with random data
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
        
        # Remove the file
        file_path.unlink()
        return True
        
    except (OSError, IOError):
        return False


def get_vault_directory() -> Path:
    """Get the default vault directory path.
    
    Returns:
        Path to the vault directory
    """
    home = Path.home()
    vault_dir = home / '.localsafe'
    vault_dir.mkdir(exist_ok=True, mode=0o700)  # Owner read/write/execute only
    return vault_dir


def validate_file_path(file_path: str) -> Path:
    """Validate and return a Path object for a file path.
    
    Args:
        file_path: String path to validate
        
    Returns:
        Validated Path object
        
    Raises:
        ValueError: If path is invalid or file doesn't exist
    """
    path = Path(file_path)
    
    if not path.exists():
        raise ValueError(f"File does not exist: {file_path}")
    
    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")
    
    return path.resolve()  # Return absolute path


def safe_filename(filename: str) -> str:
    """Sanitize a filename for safe storage.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename safe for storage
    """
    # Remove or replace dangerous characters
    unsafe_chars = '<>:"/\\|?*'
    safe_name = filename
    
    for char in unsafe_chars:
        safe_name = safe_name.replace(char, '_')
    
    # Limit length
    if len(safe_name) > 255:
        name, ext = os.path.splitext(safe_name)
        safe_name = name[:250 - len(ext)] + ext
    
    # Ensure not empty
    if not safe_name.strip():
        safe_name = 'unnamed_file'
    
    return safe_name


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte sequences.
    
    Args:
        a: First byte sequence
        b: Second byte sequence
        
    Returns:
        True if sequences are equal, False otherwise
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0