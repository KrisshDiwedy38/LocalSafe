"""
LocalSafe - Cryptographic Operations Module

This module handles all cryptographic operations including AES-256-GCM
encryption/decryption and key management using envelope encryption.
"""

from typing import Tuple, NamedTuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from utils import SecureBytes, generate_key, generate_nonce


class EncryptionResult(NamedTuple):
    """Result of an encryption operation."""
    ciphertext: bytes
    nonce: bytes
    auth_tag: bytes
    encrypted_file_key: bytes


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class EncryptionError(CryptoError):
    """Exception raised during encryption operations."""
    pass


class DecryptionError(CryptoError):
    """Exception raised during decryption operations."""
    pass


class FileEncryption:
    """Handles file encryption and decryption using AES-256-GCM with envelope encryption."""
    
    def __init__(self):
        self.vault_key: SecureBytes = None
        self._locked = True
    
    def unlock(self, vault_key: bytes) -> None:
        """Unlock the encryption module with the vault key.
        
        Args:
            vault_key: The derived vault key from master password
        """
        if self.vault_key:
            self.vault_key.clear()
        
        self.vault_key = SecureBytes(vault_key)
        self._locked = False
    
    def lock(self) -> None:
        """Lock the encryption module and clear keys from memory."""
        if self.vault_key:
            self.vault_key.clear()
            self.vault_key = None
        self._locked = True
    
    def is_locked(self) -> bool:
        """Check if the encryption module is locked.
        
        Returns:
            True if locked, False otherwise
        """
        return self._locked or self.vault_key is None
    
    def encrypt_file(self, file_data: bytes, associated_data: bytes = b"") -> EncryptionResult:
        """Encrypt file data using envelope encryption with AES-256-GCM.
        
        Args:
            file_data: The file data to encrypt
            associated_data: Optional additional authenticated data
            
        Returns:
            EncryptionResult containing ciphertext, nonce, auth_tag, and encrypted file key
            
        Raises:
            EncryptionError: If encryption fails
            RuntimeError: If vault is locked
        """
        if self.is_locked():
            raise RuntimeError("Vault is locked. Unlock with master password first.")
        
        try:
            # Generate a unique file key for this file
            file_key = generate_key(32)  # 256-bit key for AES-256
            
            # Encrypt the file data with the file key
            with SecureBytes(file_key) as secure_file_key:
                file_cipher = AESGCM(secure_file_key.data)
                nonce = generate_nonce(12)  # 96-bit nonce for GCM
                
                # Encrypt file data
                ciphertext_with_tag = file_cipher.encrypt(nonce, file_data, associated_data)
                
                # Split ciphertext and authentication tag
                # GCM appends 16-byte tag to the end
                ciphertext = ciphertext_with_tag[:-16]
                auth_tag = ciphertext_with_tag[-16:]
                
                # Encrypt the file key with the vault key (envelope encryption)
                vault_cipher = AESGCM(self.vault_key.data)
                key_nonce = generate_nonce(12)
                encrypted_file_key = vault_cipher.encrypt(key_nonce, secure_file_key.data)
                
                # Prepend nonce to encrypted file key for storage
                encrypted_file_key_with_nonce = key_nonce + encrypted_file_key
                
                return EncryptionResult(
                    ciphertext=ciphertext,
                    nonce=nonce,
                    auth_tag=auth_tag,
                    encrypted_file_key=encrypted_file_key_with_nonce
                )
                
        except Exception as e:
            raise EncryptionError(f"File encryption failed: {str(e)}") from e
    
    def decrypt_file(self, 
                    ciphertext: bytes, 
                    nonce: bytes, 
                    auth_tag: bytes,
                    encrypted_file_key: bytes,
                    associated_data: bytes = b"") -> bytes:
        """Decrypt file data using envelope decryption with AES-256-GCM.
        
        Args:
            ciphertext: The encrypted file data
            nonce: The nonce used for encryption
            auth_tag: The authentication tag
            encrypted_file_key: The encrypted file key (with nonce prepended)
            associated_data: Optional additional authenticated data
            
        Returns:
            The decrypted file data
            
        Raises:
            DecryptionError: If decryption fails
            RuntimeError: If vault is locked
        """
        if self.is_locked():
            raise RuntimeError("Vault is locked. Unlock with master password first.")
        
        try:
            # Extract nonce and encrypted file key
            key_nonce = encrypted_file_key[:12]  # First 12 bytes are nonce
            encrypted_key = encrypted_file_key[12:]  # Rest is encrypted file key
            
            # Decrypt the file key with the vault key
            vault_cipher = AESGCM(self.vault_key.data)
            file_key = vault_cipher.decrypt(key_nonce, encrypted_key)
            
            # Decrypt the file data with the file key
            with SecureBytes(file_key) as secure_file_key:
                file_cipher = AESGCM(secure_file_key.data)
                
                # Reconstruct the ciphertext with tag for GCM
                ciphertext_with_tag = ciphertext + auth_tag
                
                # Decrypt and authenticate
                plaintext = file_cipher.decrypt(nonce, ciphertext_with_tag, associated_data)
                
                return plaintext
                
        except InvalidTag as e:
            raise DecryptionError("File integrity check failed. File may be corrupted or tampered with.") from e
        except Exception as e:
            raise DecryptionError(f"File decryption failed: {str(e)}") from e
    
    def encrypt_string(self, plaintext: str) -> Tuple[bytes, bytes]:
        """Encrypt a string (like filename) with the vault key.
        
        Args:
            plaintext: The string to encrypt
            
        Returns:
            Tuple of (encrypted_data_with_nonce, nonce)
            
        Raises:
            EncryptionError: If encryption fails
            RuntimeError: If vault is locked
        """
        if self.is_locked():
            raise RuntimeError("Vault is locked. Unlock with master password first.")
        
        try:
            cipher = AESGCM(self.vault_key.data)
            nonce = generate_nonce(12)
            
            encrypted_data = cipher.encrypt(nonce, plaintext.encode('utf-8'))
            
            # Prepend nonce for storage
            return nonce + encrypted_data, nonce
            
        except Exception as e:
            raise EncryptionError(f"String encryption failed: {str(e)}") from e
    
    def decrypt_string(self, encrypted_data_with_nonce: bytes) -> str:
        """Decrypt a string (like filename) with the vault key.
        
        Args:
            encrypted_data_with_nonce: The encrypted data with nonce prepended
            
        Returns:
            The decrypted string
            
        Raises:
            DecryptionError: If decryption fails
            RuntimeError: If vault is locked
        """
        if self.is_locked():
            raise RuntimeError("Vault is locked. Unlock with master password first.")
        
        try:
            nonce = encrypted_data_with_nonce[:12]
            encrypted_data = encrypted_data_with_nonce[12:]
            
            cipher = AESGCM(self.vault_key.data)
            plaintext_bytes = cipher.decrypt(nonce, encrypted_data)
            
            return plaintext_bytes.decode('utf-8')
            
        except InvalidTag as e:
            raise DecryptionError("String integrity check failed.") from e
        except Exception as e:
            raise DecryptionError(f"String decryption failed: {str(e)}") from e
    
    def __del__(self):
        """Ensure keys are cleared when object is destroyed."""
        self.lock()