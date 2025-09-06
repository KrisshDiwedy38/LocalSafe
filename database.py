"""
LocalSafe - Database Management Module

This module handles SQLite database operations for storing encrypted
file metadata, vault configuration, and security settings.
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Optional, Dict, Any, NamedTuple
from pathlib import Path

from utils import generate_salt


class FileRecord(NamedTuple):
    """Represents a file record in the database."""
    id: int
    encrypted_filename: bytes
    original_size: int
    encrypted_size: int
    created_at: str
    modified_at: str
    encrypted_file_key: bytes
    nonce: bytes
    auth_tag: bytes
    integrity_hash: str


class VaultConfig(NamedTuple):
    """Represents vault configuration."""
    id: int
    created_at: str
    password_hash: str
    salt: bytes
    settings: Dict[str, Any]


class DatabaseError(Exception):
    """Base exception for database operations."""
    pass


class VaultDatabase:
    """Manages the SQLite database for the encrypted vault."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
    
    def connect(self) -> None:
        """Establish connection to the database with security settings."""
        try:
            self.connection = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                timeout=30.0
            )
            
            # Configure secure settings
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=FULL")
            self.connection.execute("PRAGMA secure_delete=ON")
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA temp_store=MEMORY")
            
            # Set row factory for convenient access
            self.connection.row_factory = sqlite3.Row
            
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to connect to database: {str(e)}") from e
    
    def disconnect(self) -> None:
        """Close the database connection."""
        if self.connection:
            try:
                self.connection.close()
            except sqlite3.Error:
                pass  # Ignore errors during close
            finally:
                self.connection = None
    
    def initialize_database(self, password_hash: str, salt: bytes) -> None:
        """Initialize a new vault database with required tables.
        
        Args:
            password_hash: The Argon2id hash of the master password
            salt: The salt used for key derivation
            
        Raises:
            DatabaseError: If initialization fails
        """
        if not self.connection:
            raise DatabaseError("Database not connected")
        
        try:
            cursor = self.connection.cursor()
            
            # Create vault configuration table
            cursor.execute("""
                CREATE TABLE vault_config (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    created_at TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    settings TEXT NOT NULL DEFAULT '{}',
                    UNIQUE(id)
                )
            """)
            
            # Create files table
            cursor.execute("""
                CREATE TABLE files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    encrypted_filename BLOB NOT NULL,
                    original_size INTEGER NOT NULL,
                    encrypted_size INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    modified_at TEXT NOT NULL,
                    encrypted_file_key BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    auth_tag BLOB NOT NULL,
                    integrity_hash TEXT NOT NULL
                )
            """)
            
            # Create indexes for performance
            cursor.execute("""
                CREATE INDEX idx_files_created_at ON files(created_at)
            """)
            
            cursor.execute("""
                CREATE INDEX idx_files_integrity_hash ON files(integrity_hash)
            """)
            
            # Insert initial vault configuration
            now = datetime.utcnow().isoformat()
            default_settings = {
                "version": "1.0",
                "auto_lock_timeout": 300,  # 5 minutes
                "max_file_size": 100 * 1024 * 1024,  # 100 MB
                "compression_enabled": True
            }
            
            cursor.execute("""
                INSERT INTO vault_config 
                (id, created_at, password_hash, salt, settings)
                VALUES (1, ?, ?, ?, ?)
            """, (now, password_hash, salt, json.dumps(default_settings)))
            
            self.connection.commit()
            
        except sqlite3.Error as e:
            self.connection.rollback()
            raise DatabaseError(f"Database initialization failed: {str(e)}") from e
    
    def get_vault_config(self) -> VaultConfig:
        """Retrieve the vault configuration.
        
        Returns:
            VaultConfig object with configuration data
            
        Raises:
            DatabaseError: If retrieval fails
        """
        if not self.connection:
            raise DatabaseError("Database not connected")
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT * FROM vault_config WHERE id = 1")
            row = cursor.fetchone()
            
            if not row:
                raise DatabaseError("Vault configuration not found")
            
            return VaultConfig(
                id=row['id'],
                created_at=row['created_at'],
                password_hash=row['password_hash'],
                salt=row['salt'],
                settings=json.loads(row['settings'])
            )
            
        except (sqlite3.Error, json.JSONDecodeError) as e:
            raise DatabaseError(f"Failed to retrieve vault config: {str(e)}") from e
    
    def update_vault_settings(self, settings: Dict[str, Any]) -> None:
        """Update vault settings.
        
        Args:
            settings: Dictionary of settings to update
            
        Raises:
            DatabaseError: If update fails
        """
        if not self.connection:
            raise DatabaseError("Database not connected")
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                UPDATE vault_config 
                SET settings = ? 
                WHERE id = 1
            """, (json.dumps(settings),))
            
            if cursor.rowcount == 0:
                raise DatabaseError("Vault configuration not found")
            
            self.connection.commit()
            
        except sqlite3.Error as e:
            self.connection.rollback()
            raise DatabaseError(f"Failed to update vault settings: {str(e)}") from e
    
    def add_file(self, 
                 encrypted_filename: bytes,
                 original_size: int,
                 encrypted_size: int,
                 encrypted_file_key: bytes,
                 nonce: bytes,
                 auth_tag: bytes,
                 integrity_hash: str) -> int:
        """Add a new file record to the database.
        
        Args:
            encrypted_filename: Encrypted original filename
            original_size: Size of original file in bytes
            encrypted_size: Size of encrypted file in bytes
            encrypted_file_key: Encrypted file key (with envelope encryption)
            nonce: Nonce used for file encryption
            auth_tag: Authentication tag from GCM
            integrity_hash: SHA-256 hash of original file
            
        Returns:
            The ID of the newly inserted file record
            
        Raises:
            DatabaseError: If insertion fails
        """
        if not self.connection:
            raise DatabaseError("Database not connected")
        
        try:
            cursor = self.connection.cursor()
            now = datetime.utcnow().isoformat()
            
            cursor.execute("""
                INSERT INTO files 
                (encrypted_filename, original_size, encrypted_size, created_at, 
                 modified_at, encrypted_file_key, nonce, auth_tag, integrity_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (encrypted_filename, original_size, encrypted_size, now, now,
                  encrypted_file_key, nonce, auth_tag, integrity_hash))
            
            file_id = cursor.lastrowid
            self.connection.commit()
            
            return file_id
            
        except sqlite3.Error as e:
            self.connection.rollback()
            raise DatabaseError(f"Failed to add file record: {str(e)}") from e
    
    def get_file_by_filename(self, encrypted_filename: bytes) -> Optional[FileRecord]:
        """Retrieve a file record by encrypted filename.
        
        Args:
            encrypted_filename: The encrypted filename to search for
            
        Returns:
            FileRecord if found, None otherwise
            
        Raises:
            DatabaseError: If query fails
        """
        if not self.connection:
            raise DatabaseError("Database not connected")
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT * FROM files WHERE encrypted_filename = ?
            """, (encrypted_filename,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return FileRecord(
                id=row['id'],
                encrypted_filename=row['encrypted_filename'],
                original_size=row['original_size'],
                encrypted_size=row['encrypted_size'],
                created_at=row['created_at'],
                modified_at=row['modified_at'],
                encrypted_file_key=row['encrypted_file_key'],
                nonce=row['nonce'],
                auth_tag=row['auth_tag'],
                integrity_hash=row['integrity_hash']
            )
            
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to retrieve file: {str(e)}") from e
    
    def get_all_files(self) -> List[FileRecord]:
        """Retrieve all file records.
        
        Returns:
            List of FileRecord objects
            
        Raises:
            DatabaseError: If query fails
        """
        if not self.connection:
            raise DatabaseError("Database not connected")
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT * FROM files ORDER BY created_at DESC
            """)
            
            records = []
            for row in cursor.fetchall():
                records.append(FileRecord(
                    id=row['id'],
                    encrypted_filename=row['encrypted_filename'],
                    original_size=row['original_size'],
                    encrypted_size=row['encrypted_size'],
                    created_at=row['created_at'],
                    modified_at=row['modified_at'],
                    encrypted_file_key=row['encrypted_file_key'],
                    nonce=row['nonce'],
                    auth_tag=row['auth_tag'],
                    integrity_hash=row['integrity_hash']
                ))
            
            return records
            
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to retrieve files: {str(e)}") from e
    
    def delete_file(self, file_id: int) -> bool:
        """Delete a file record by ID.
        
        Args:
            file_id: The ID of the file to delete
            
        Returns:
            True if file was deleted, False if not found
            
        Raises:
            DatabaseError: If deletion fails
        """
        if not self.connection:
            raise DatabaseError("Database not connected")
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))
            
            deleted = cursor.rowcount > 0
            self.connection.commit()
            
            return deleted
            
        except sqlite3.Error as e:
            self.connection.rollback()
            raise DatabaseError(f"Failed to delete file: {str(e)}") from e
    
    def update_file_hash(self, file_id: int, new_hash: str) -> None:
        """Update the integrity hash for a file record.
        
        Args:
            file_id: The ID of the file to update
            new_hash: The new integrity hash
            
        Raises:
            DatabaseError: If update fails
        """
        if not self.connection:
            raise DatabaseError("Database not connected")
        
        try:
            cursor = self.connection.cursor()
            now = datetime.utcnow().isoformat()
            
            cursor.execute("""
                UPDATE files 
                SET integrity_hash = ?, modified_at = ?
                WHERE id = ?
            """, (new_hash, now, file_id))
            
            if cursor.rowcount == 0:
                raise DatabaseError("File record not found")
            
            self.connection.commit()
            
        except sqlite3.Error as e:
            self.connection.rollback()
            raise DatabaseError(f"Failed to update file hash: {str(e)}") from e
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics.
        
        Returns:
            Dictionary containing database statistics
            
        Raises:
            DatabaseError: If query fails
        """
        if not self.connection:
            raise DatabaseError("Database not connected")
        
        try:
            cursor = self.connection.cursor()
            
            # Get file count and total sizes
            cursor.execute("""
                SELECT 
                    COUNT(*) as file_count,
                    SUM(original_size) as total_original_size,
                    SUM(encrypted_size) as total_encrypted_size
                FROM files
            """)
            
            stats_row = cursor.fetchone()
            
            # Get database file size
            db_size = self.db_path.stat().st_size if self.db_path.exists() else 0
            
            return {
                'file_count': stats_row['file_count'] or 0,
                'total_original_size': stats_row['total_original_size'] or 0,
                'total_encrypted_size': stats_row['total_encrypted_size'] or 0,
                'database_size': db_size,
                'database_path': str(self.db_path)
            }
            
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get database stats: {str(e)}") from e
    
    def vacuum_database(self) -> None:
        """Optimize the database by reclaiming unused space.
        
        Raises:
            DatabaseError: If vacuum fails
        """
        if not self.connection:
            raise DatabaseError("Database not connected")
        
        try:
            # Vacuum requires autocommit mode
            self.connection.isolation_level = None
            self.connection.execute("VACUUM")
            self.connection.isolation_level = ''
            
        except sqlite3.Error as e:
            raise DatabaseError(f"Database vacuum failed: {str(e)}") from e
    
    def verify_database_integrity(self) -> bool:
        """Verify the integrity of the database.
        
        Returns:
            True if database is intact, False otherwise
            
        Raises:
            DatabaseError: If integrity check fails
        """
        if not self.connection:
            raise DatabaseError("Database not connected")
        
        try:
            cursor = self.connection.cursor()
            cursor.execute("PRAGMA integrity_check")
            result = cursor.fetchone()
            
            return result[0] == 'ok'
            
        except sqlite3.Error as e:
            raise DatabaseError(f"Database integrity check failed: {str(e)}") from e
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.disconnect()
    
    def __del__(self):
        """Ensure database connection is closed."""
        self.disconnect()