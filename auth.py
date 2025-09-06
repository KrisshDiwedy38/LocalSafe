"""
LocalSafe - Authentication and Key Derivation Module

This module handles master password authentication using Argon2id
and derives the vault key from the master password.
"""

import getpass
from typing import Optional, Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, HashingError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils import SecureBytes, generate_salt, constant_time_compare


class AuthError(Exception):
    """Base exception for authentication operations."""
    pass


class InvalidPasswordError(AuthError):
    """Exception raised when password verification fails."""
    pass


class KeyDerivationError(AuthError):
    """Exception raised during key derivation operations."""
    pass


class MasterPasswordAuth:
    """Handles master password authentication and key derivation."""
    
    def __init__(self):
        # Configure Argon2id with secure parameters
        self.password_hasher = PasswordHasher(
            time_cost=3,        # 3 iterations (recommended minimum)
            memory_cost=65536,  # 64 MB memory usage
            parallelism=1,      # Single thread (deterministic)
            hash_len=32,        # 32-byte hash output
            salt_len=16,        # 16-byte salt
            encoding='utf-8'
        )
    
    def hash_password(self, password: str) -> str:
        """Hash a password using Argon2id.
        
        Args:
            password: The plaintext password to hash
            
        Returns:
            The Argon2id hash string
            
        Raises:
            AuthError: If hashing fails
        """
        try:
            return self.password_hasher.hash(password)
        except HashingError as e:
            raise AuthError(f"Password hashing failed: {str(e)}") from e
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify a password against its hash.
        
        Args:
            password: The plaintext password to verify
            hashed_password: The stored Argon2id hash
            
        Returns:
            True if password is correct, False otherwise
        """
        try:
            self.password_hasher.verify(hashed_password, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False
    
    def derive_vault_key(self, password: str, salt: bytes, iterations: int = 100000) -> bytes:
        """Derive the vault key from the master password using PBKDF2-HMAC-SHA256.
        
        Args:
            password: The master password
            salt: Random salt for key derivation
            iterations: Number of PBKDF2 iterations (default: 100,000)
            
        Returns:
            32-byte derived key for AES-256
            
        Raises:
            KeyDerivationError: If key derivation fails
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 32 bytes for AES-256
                salt=salt,
                iterations=iterations,
            )
            
            return kdf.derive(password.encode('utf-8'))
            
        except Exception as e:
            raise KeyDerivationError(f"Key derivation failed: {str(e)}") from e
    
    def prompt_password(self, prompt: str = "Master password: ", confirm: bool = False) -> str:
        """Securely prompt for a password.
        
        Args:
            prompt: The prompt message to display
            confirm: Whether to ask for password confirmation
            
        Returns:
            The entered password
            
        Raises:
            AuthError: If passwords don't match (when confirming)
        """
        try:
            password = getpass.getpass(prompt)
            
            if confirm:
                confirm_password = getpass.getpass("Confirm master password: ")
                if password != confirm_password:
                    raise AuthError("Passwords do not match")
            
            return password
            
        except KeyboardInterrupt:
            raise AuthError("Password entry cancelled")
        except EOFError:
            raise AuthError("Password entry failed")
    
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validate password strength according to security best practices.
        
        Args:
            password: The password to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
        
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if not (has_lower and has_upper and has_digit and has_special):
            return False, ("Password must contain lowercase, uppercase, "
                          "digit, and special character")
        
        # Check for common weak patterns
        common_patterns = [
            "password", "123456", "qwerty", "admin", "letmein",
            "welcome", "monkey", "dragon", "master", "login"
        ]
        
        password_lower = password.lower()
        for pattern in common_patterns:
            if pattern in password_lower:
                return False, f"Password contains common pattern: {pattern}"
        
        return True, ""
    
    def create_master_password(self) -> Tuple[str, str]:
        """Interactive creation of a new master password with validation.
        
        Returns:
            Tuple of (password, hashed_password)
            
        Raises:
            AuthError: If password creation fails
        """
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                password = self.prompt_password("Create master password: ", confirm=True)
                
                # Validate password strength
                is_valid, error_msg = self.validate_password_strength(password)
                if not is_valid:
                    print(f"Password validation failed: {error_msg}")
                    if attempt < max_attempts - 1:
                        print("Please try again.\n")
                        continue
                    else:
                        raise AuthError(f"Maximum attempts exceeded: {error_msg}")
                
                # Hash the password
                hashed_password = self.hash_password(password)
                
                return password, hashed_password
                
            except AuthError:
                if attempt < max_attempts - 1:
                    print("Please try again.\n")
                    continue
                else:
                    raise
        
        raise AuthError("Failed to create master password after maximum attempts")
    
    def authenticate_user(self, hashed_password: str) -> str:
        """Authenticate user with master password.
        
        Args:
            hashed_password: The stored password hash
            
        Returns:
            The verified password
            
        Raises:
            InvalidPasswordError: If authentication fails
        """
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                password = self.prompt_password("Enter master password: ")
                
                if self.verify_password(password, hashed_password):
                    return password
                else:
                    if attempt < max_attempts - 1:
                        print("Incorrect password. Please try again.\n")
                    else:
                        raise InvalidPasswordError("Authentication failed after maximum attempts")
                        
            except KeyboardInterrupt:
                raise InvalidPasswordError("Authentication cancelled")
        
        raise InvalidPasswordError("Authentication failed")


class SecureSession:
    """Manages a secure session with derived keys."""
    
    def __init__(self, auth: MasterPasswordAuth):
        self.auth = auth
        self.vault_key: Optional[SecureBytes] = None
        self.salt: Optional[bytes] = None
    
    def start_session(self, password: str, salt: bytes) -> bytes:
        """Start a secure session by deriving the vault key.
        
        Args:
            password: The verified master password
            salt: The salt for key derivation
            
        Returns:
            The derived vault key
        """
        if self.vault_key:
            self.vault_key.clear()
        
        self.salt = salt
        vault_key = self.auth.derive_vault_key(password, salt)
        self.vault_key = SecureBytes(vault_key)
        
        return vault_key
    
    def get_vault_key(self) -> bytes:
        """Get the current vault key.
        
        Returns:
            The vault key
            
        Raises:
            RuntimeError: If session is not active
        """
        if not self.vault_key:
            raise RuntimeError("No active session. Authenticate first.")
        
        return self.vault_key.data
    
    def end_session(self) -> None:
        """End the secure session and clear keys from memory."""
        if self.vault_key:
            self.vault_key.clear()
            self.vault_key = None
        self.salt = None
    
    def is_active(self) -> bool:
        """Check if session is active.
        
        Returns:
            True if session is active, False otherwise
        """
        return self.vault_key is not None
    
    def __del__(self):
        """Ensure session is ended when object is destroyed."""
        self.end_session()