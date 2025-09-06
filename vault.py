"""
LocalSafe - Vault Manager Module

This module provides the main vault management functionality,
coordinating between authentication, encryption, database, and locking.
"""

import os
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime

from auth import MasterPasswordAuth, SecureSession, AuthError, InvalidPasswordError
from crypto import FileEncryption, EncryptionError, DecryptionError
from database import VaultDatabase, FileRecord, DatabaseError
from lock import SessionManager, InactivityMonitor
from utils import (
    get_vault_directory, validate_file_path, compute_file_hash,
    safe_filename, generate_salt, SecureBytes
)


class VaultError(Exception):
    """Base exception for vault operations."""
    pass


class VaultNotInitializedError(VaultError):
    """Exception raised when vault is not initialized."""
    pass


class VaultLockedError(VaultError):
    """Exception raised when vault is locked."""
    pass


class FileNotFoundError(VaultError):
    """Exception raised when file is not found in vault."""
    pass


class VaultManager:
    """Main vault manager coordinating all vault operations."""
    
    def __init__(self, vault_directory: Optional[Path] = None):
        """Initialize the vault manager.
        
        Args:
            vault_directory: Custom vault directory (default: ~/.localsafe)
        """
        self.vault_dir = vault_directory or get_vault_directory()
        self.vault_file_dir = self.vault_dir / 'files'
        self.db_path = self.vault_dir / 'vault.db'
        
        # Initialize components
        self.auth = MasterPasswordAuth()
        self.session = SecureSession(self.auth)
        self.crypto = FileEncryption()
        self.database = VaultDatabase(self.db_path)
        
        # Session management with auto-lock
        self.session_manager = SessionManager(auto_lock_timeout=300)
        self.inactivity_monitor = InactivityMonitor(self.session_manager)
        
        # Register callbacks
        self.session_manager.add_lock_callback(self._on_auto_lock)
        
        # Vault state
        self._vault_config: Optional[Dict[str, Any]] = None
    
    def is_initialized(self) -> bool:
        """Check if the vault is initialized.
        
        Returns:
            True if vault is initialized, False otherwise
        """
        return self.db_path.exists() and self.vault_file_dir.exists()
    
    def initialize_vault(self) -> None:
        """Initialize a new vault with master password setup.
        
        Raises:
            VaultError: If initialization fails
        """
        if self.is_initialized():
            raise VaultError("Vault is already initialized")
        
        try:
            print("Initializing new LocalSafe vault...")
            print("Please create a strong master password.")
            print("Requirements: 12+ characters, uppercase, lowercase, digit, special character")
            
            # Create master password
            password, hashed_password = self.auth.create_master_password()
            
            # Generate salt for key derivation
            salt = generate_salt(32)
            
            # Create vault directory structure
            self.vault_dir.mkdir(exist_ok=True, mode=0o700)
            self.vault_file_dir.mkdir(exist_ok=True, mode=0o700)
            
            # Initialize database
            with self.database:
                self.database.initialize_database(hashed_password, salt)
            
            print(f"Vault initialized successfully at: {self.vault_dir}")
            print("Use 'localsafe unlock' to start using your vault.")
            
        except (AuthError, DatabaseError) as e:
            # Cleanup on failure
            if self.vault_dir.exists():
                shutil.rmtree(self.vault_dir, ignore_errors=True)
            raise VaultError(f"Vault initialization failed: {str(e)}") from e
    
    def unlock_vault(self) -> None:
        """Unlock the vault with master password authentication.
        
        Raises:
            VaultError: If unlock fails
        """
        if not self.is_initialized():
            raise VaultNotInitializedError("Vault is not initialized. Run 'localsafe init' first.")
        
        if not self.crypto.is_locked():
            print("Vault is already unlocked.")
            return
        
        try:
            # Get vault configuration
            with self.database:
                config = self.database.get_vault_config()
                self._vault_config = config.settings
            
            # Authenticate user
            password = self.auth.authenticate_user(config.password_hash)
            
            # Start secure session
            vault_key = self.session.start_session(password, config.salt)
            
            # Unlock crypto module
            self.crypto.unlock(vault_key)
            
            # Start session management
            auto_lock_timeout = self._vault_config.get('auto_lock_timeout', 300)
            self.session_manager.auto_lock.set_timeout(auto_lock_timeout)
            self.session_manager.start_session()
            self.inactivity_monitor.start_monitoring()
            
            print("Vault unlocked successfully.")
            
            # Show session info
            time_until_lock = auto_lock_timeout // 60
            print(f"Auto-lock enabled: {time_until_lock} minutes of inactivity")
            
        except (InvalidPasswordError, DatabaseError) as e:
            raise VaultError(f"Failed to unlock vault: {str(e)}") from e
    
    def lock_vault(self) -> None:
        """Lock the vault and clear sensitive data from memory.
        
        Raises:
            VaultError: If lock fails
        """
        try:
            # Stop monitoring
            self.inactivity_monitor.stop_monitoring()
            
            # End session
            self.session_manager.end_session()
            
            # Lock crypto module
            self.crypto.lock()
            
            # End secure session
            self.session.end_session()
            
            # Clear config
            self._vault_config = None
            
            print("Vault locked successfully.")
            
        except Exception as e:
            # Always try to clear sensitive data even if an error occurs
            self._force_lock()
            raise VaultError(f"Failed to lock vault cleanly: {str(e)}") from e
    
    def add_file(self, file_path: str) -> None:
        """Add a file to the vault.
        
        Args:
            file_path: Path to the file to add
            
        Raises:
            VaultError: If file addition fails
        """
        if not self.is_initialized():
            raise VaultNotInitializedError("Vault is not initialized")
        
        if self.crypto.is_locked():
            raise VaultLockedError("Vault is locked. Unlock first.")
        
        try:
            # Validate and get file path
            source_path = validate_file_path(file_path)
            filename = source_path.name
            
            # Record activity
            self.session_manager.record_activity("add_file")
            
            # Check file size limit
            file_size = source_path.stat().st_size
            max_size = self._vault_config.get('max_file_size', 100 * 1024 * 1024)
            if file_size > max_size:
                raise VaultError(f"File too large: {file_size} bytes (max: {max_size})")
            
            # Check if file already exists
            encrypted_filename, _ = self.crypto.encrypt_string(filename)
            with self.database:
                existing_file = self.database.get_file_by_filename(encrypted_filename)
                if existing_file:
                    raise VaultError(f"File '{filename}' already exists in vault")
                
                # Read and encrypt file
                print(f"Encrypting file: {filename}")
                with open(source_path, 'rb') as f:
                    file_data = f.read()
                
                # Compute integrity hash
                integrity_hash = compute_file_hash(source_path)
                
                # Encrypt file data
                encryption_result = self.crypto.encrypt_file(file_data)
                
                # Store encrypted file
                encrypted_file_path = self._get_encrypted_file_path(encrypted_filename)
                with open(encrypted_file_path, 'wb') as f:
                    f.write(encryption_result.ciphertext)
                
                # Set secure permissions
                encrypted_file_path.chmod(0o600)  # Owner read/write only
                
                # Add record to database
                file_id = self.database.add_file(
                    encrypted_filename=encrypted_filename,
                    original_size=file_size,
                    encrypted_size=len(encryption_result.ciphertext),
                    encrypted_file_key=encryption_result.encrypted_file_key,
                    nonce=encryption_result.nonce,
                    auth_tag=encryption_result.auth_tag,
                    integrity_hash=integrity_hash
                )
                
                print(f"File '{filename}' added to vault successfully (ID: {file_id})")
                
        except (EncryptionError, DatabaseError, OSError) as e:
            raise VaultError(f"Failed to add file: {str(e)}") from e
    
    def get_file(self, filename: str, output_path: str) -> None:
        """Retrieve and decrypt a file from the vault.
        
        Args:
            filename: Name of the file to retrieve
            output_path: Path where to save the decrypted file
            
        Raises:
            VaultError: If file retrieval fails
        """
        if not self.is_initialized():
            raise VaultNotInitializedError("Vault is not initialized")
        
        if self.crypto.is_locked():
            raise VaultLockedError("Vault is locked. Unlock first.")
        
        try:
            # Record activity
            self.session_manager.record_activity("get_file")
            
            # Find file record
            encrypted_filename, _ = self.crypto.encrypt_string(filename)
            
            with self.database:
                file_record = self.database.get_file_by_filename(encrypted_filename)
                if not file_record:
                    raise FileNotFoundError(f"File '{filename}' not found in vault")
                
                # Read encrypted file
                encrypted_file_path = self._get_encrypted_file_path(encrypted_filename)
                if not encrypted_file_path.exists():
                    raise VaultError(f"Encrypted file missing: {filename}")
                
                print(f"Decrypting file: {filename}")
                with open(encrypted_file_path, 'rb') as f:
                    ciphertext = f.read()
                
                # Decrypt file
                plaintext = self.crypto.decrypt_file(
                    ciphertext=ciphertext,
                    nonce=file_record.nonce,
                    auth_tag=file_record.auth_tag,
                    encrypted_file_key=file_record.encrypted_file_key
                )
                
                # Write decrypted file
                output_file = Path(output_path)
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_file, 'wb') as f:
                    f.write(plaintext)
                
                # Verify integrity
                decrypted_hash = compute_file_hash(output_file)
                if decrypted_hash != file_record.integrity_hash:
                    output_file.unlink()  # Delete corrupted file
                    raise VaultError(f"File integrity check failed for '{filename}'")
                
                print(f"File '{filename}' retrieved successfully to: {output_path}")
                
        except (DecryptionError, DatabaseError, OSError) as e:
            raise VaultError(f"Failed to retrieve file: {str(e)}") from e
    
    def list_files(self) -> List[Dict[str, Any]]:
        """List all files in the vault.
        
        Returns:
            List of dictionaries containing file information
            
        Raises:
            VaultError: If listing fails
        """
        if not self.is_initialized():
            raise VaultNotInitializedError("Vault is not initialized")
        
        if self.crypto.is_locked():
            raise VaultLockedError("Vault is locked. Unlock first.")
        
        try:
            # Record activity
            self.session_manager.record_activity("list_files")
            
            with self.database:
                file_records = self.database.get_all_files()
                
                files = []
                for record in file_records:
                    try:
                        # Decrypt filename
                        filename = self.crypto.decrypt_string(record.encrypted_filename)
                        
                        files.append({
                            'id': record.id,
                            'filename': filename,
                            'size': record.original_size,
                            'encrypted_size': record.encrypted_size,
                            'created_at': record.created_at,
                            'modified_at': record.modified_at,
                            'integrity_hash': record.integrity_hash
                        })
                        
                    except DecryptionError:
                        # Skip files that can't be decrypted (corrupted metadata)
                        files.append({
                            'id': record.id,
                            'filename': '[CORRUPTED]',
                            'size': record.original_size,
                            'encrypted_size': record.encrypted_size,
                            'created_at': record.created_at,
                            'modified_at': record.modified_at,
                            'integrity_hash': '[ERROR]'
                        })
                
                return files
                
        except DatabaseError as e:
            raise VaultError(f"Failed to list files: {str(e)}") from e
    
    def remove_file(self, filename: str) -> None:
        """Remove a file from the vault.
        
        Args:
            filename: Name of the file to remove
            
        Raises:
            VaultError: If file removal fails
        """
        if not self.is_initialized():
            raise VaultNotInitializedError("Vault is not initialized")
        
        if self.crypto.is_locked():
            raise VaultLockedError("Vault is locked. Unlock first.")
        
        try:
            # Record activity
            self.session_manager.record_activity("remove_file")
            
            # Find file record
            encrypted_filename, _ = self.crypto.encrypt_string(filename)
            
            with self.database:
                file_record = self.database.get_file_by_filename(encrypted_filename)
                if not file_record:
                    raise FileNotFoundError(f"File '{filename}' not found in vault")
                
                # Remove encrypted file
                encrypted_file_path = self._get_encrypted_file_path(encrypted_filename)
                if encrypted_file_path.exists():
                    encrypted_file_path.unlink()
                
                # Remove database record
                self.database.delete_file(file_record.id)
                
                print(f"File '{filename}' removed from vault successfully")
                
        except DatabaseError as e:
            raise VaultError(f"Failed to remove file: {str(e)}") from e
    
    def get_vault_status(self) -> Dict[str, Any]:
        """Get current vault status and statistics.
        
        Returns:
            Dictionary containing vault status information
        """
        try:
            status = {
                'initialized': self.is_initialized(),
                'locked': self.crypto.is_locked(),
                'vault_directory': str(self.vault_dir),
                'session_info': self.session_manager.get_session_info()
            }
            
            if self.is_initialized():
                with self.database:
                    db_stats = self.database.get_database_stats()
                    status.update(db_stats)
            
            return status
            
        except Exception as e:
            return {
                'initialized': self.is_initialized(),
                'locked': True,
                'error': str(e)
            }
    
    def update_vault_settings(self, settings: Dict[str, Any]) -> None:
        """Update vault settings.
        
        Args:
            settings: Dictionary of settings to update
            
        Raises:
            VaultError: If update fails
        """
        if not self.is_initialized():
            raise VaultNotInitializedError("Vault is not initialized")
        
        try:
            with self.database:
                # Get current settings
                config = self.database.get_vault_config()
                current_settings = config.settings
                
                # Update with new settings
                current_settings.update(settings)
                
                # Validate settings
                self._validate_settings(current_settings)
                
                # Save updated settings
                self.database.update_vault_settings(current_settings)
                self._vault_config = current_settings
                
                # Apply runtime settings
                if 'auto_lock_timeout' in settings and not self.crypto.is_locked():
                    self.session_manager.auto_lock.set_timeout(settings['auto_lock_timeout'])
                
                print("Vault settings updated successfully")
                
        except DatabaseError as e:
            raise VaultError(f"Failed to update settings: {str(e)}") from e
    
    def verify_vault_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of the vault and all files.
        
        Returns:
            Dictionary containing integrity check results
        """
        if not self.is_initialized():
            raise VaultNotInitializedError("Vault is not initialized")
        
        results = {
            'database_ok': False,
            'files_checked': 0,
            'files_ok': 0,
            'corrupted_files': [],
            'missing_files': [],
            'errors': []
        }
        
        try:
            with self.database:
                # Check database integrity
                results['database_ok'] = self.database.verify_database_integrity()
                
                if not results['database_ok']:
                    results['errors'].append("Database integrity check failed")
                
                # Check files if vault is unlocked
                if not self.crypto.is_locked():
                    file_records = self.database.get_all_files()
                    results['files_checked'] = len(file_records)
                    
                    for record in file_records:
                        try:
                            filename = self.crypto.decrypt_string(record.encrypted_filename)
                            encrypted_file_path = self._get_encrypted_file_path(record.encrypted_filename)
                            
                            if not encrypted_file_path.exists():
                                results['missing_files'].append(filename)
                            else:
                                # Could add more integrity checks here
                                results['files_ok'] += 1
                                
                        except Exception as e:
                            results['corrupted_files'].append(f"Record ID {record.id}: {str(e)}")
                else:
                    results['errors'].append("Vault is locked - cannot verify file integrity")
            
            return results
            
        except Exception as e:
            results['errors'].append(f"Integrity check failed: {str(e)}")
            return results
    
    def _get_encrypted_file_path(self, encrypted_filename: bytes) -> Path:
        """Get the path for an encrypted file storage.
        
        Args:
            encrypted_filename: The encrypted filename bytes
            
        Returns:
            Path object for the encrypted file
        """
        # Use hash of encrypted filename to avoid filesystem issues
        import hashlib
        filename_hash = hashlib.sha256(encrypted_filename).hexdigest()
        return self.vault_file_dir / f"{filename_hash}.enc"
    
    def _validate_settings(self, settings: Dict[str, Any]) -> None:
        """Validate vault settings.
        
        Args:
            settings: Settings dictionary to validate
            
        Raises:
            VaultError: If settings are invalid
        """
        # Validate auto-lock timeout
        if 'auto_lock_timeout' in settings:
            timeout = settings['auto_lock_timeout']
            if not isinstance(timeout, int) or timeout < 60:
                raise VaultError("Auto-lock timeout must be at least 60 seconds")
        
        # Validate max file size
        if 'max_file_size' in settings:
            max_size = settings['max_file_size']
            if not isinstance(max_size, int) or max_size < 1024:
                raise VaultError("Max file size must be at least 1024 bytes")
    
    def _on_auto_lock(self) -> None:
        """Handle auto-lock event.
        
        This method is called when the auto-lock timer expires.
        """
        try:
            print("\nAuto-lock triggered due to inactivity")
            self.lock_vault()
        except Exception as e:
            print(f"Warning: Auto-lock failed: {str(e)}")
            self._force_lock()
    
    def _force_lock(self) -> None:
        """Force lock the vault (emergency cleanup).
        
        This method clears all sensitive data regardless of errors.
        """
        try:
            self.inactivity_monitor.stop_monitoring()
        except:
            pass
        
        try:
            self.session_manager.end_session()
        except:
            pass
        
        try:
            self.crypto.lock()
        except:
            pass
        
        try:
            self.session.end_session()
        except:
            pass
        
        self._vault_config = None
    
    def __del__(self):
        """Ensure vault is locked when object is destroyed."""
        try:
            self._force_lock()
        except:
            pass