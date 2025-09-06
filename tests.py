#!/usr/bin/env python3
"""
LocalSafe - Unit Tests

Comprehensive test suite for the LocalSafe encrypted file vault system.
Tests all major components including crypto, auth, database, and vault operations.
"""

import os
import sys
import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    SecureBytes, generate_salt, generate_key, generate_nonce,
    compute_file_hash, compute_data_hash, safe_filename, constant_time_compare
)
from crypto import FileEncryption, EncryptionError, DecryptionError
from auth import MasterPasswordAuth, SecureSession, AuthError, InvalidPasswordError
from database import VaultDatabase, DatabaseError
from vault import VaultManager, VaultError, VaultNotInitializedError, VaultLockedError


class TestUtils(unittest.TestCase):
    """Test utility functions."""
    
    def test_secure_bytes(self):
        """Test SecureBytes wrapper."""
        test_data = b"sensitive_data_123"
        
        with SecureBytes(test_data) as secure:
            self.assertEqual(secure.data, test_data)
            self.assertFalse(secure._cleared)
        
        # Should be cleared after context
        self.assertTrue(secure._cleared)
        
        with self.assertRaises(RuntimeError):
            _ = secure.data
    
    def test_generate_functions(self):
        """Test cryptographic generation functions."""
        salt = generate_salt(32)
        self.assertEqual(len(salt), 32)
        self.assertIsInstance(salt, bytes)
        
        key = generate_key(32)
        self.assertEqual(len(key), 32)
        self.assertIsInstance(key, bytes)
        
        nonce = generate_nonce(12)
        self.assertEqual(len(nonce), 12)
        self.assertIsInstance(nonce, bytes)
        
        # Test randomness (different calls should produce different results)
        self.assertNotEqual(generate_salt(32), generate_salt(32))
    
    def test_file_hashing(self):
        """Test file and data hashing."""
        test_data = b"Hello, World!"
        
        # Test data hash
        hash1 = compute_data_hash(test_data)
        hash2 = compute_data_hash(test_data)
        self.assertEqual(hash1, hash2)  # Same data should produce same hash
        self.assertEqual(len(hash1), 64)  # SHA-256 hex is 64 characters
        
        # Test file hash
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(test_data)
            tmp_path = Path(tmp.name)
        
        try:
            file_hash = compute_file_hash(tmp_path)
            self.assertEqual(file_hash, hash1)  # Should match data hash
        finally:
            tmp_path.unlink()
    
    def test_safe_filename(self):
        """Test filename sanitization."""
        unsafe_names = [
            "file<>name.txt",
            "file:name.txt",
            "file|name.txt",
            "very_long_filename" + "x" * 300,
            "",
            "   "
        ]
        
        for unsafe in unsafe_names:
            safe = safe_filename(unsafe)
            self.assertNotIn('<', safe)
            self.assertNotIn('>', safe)
            self.assertNotIn(':', safe)
            self.assertNotIn('|', safe)
            self.assertLessEqual(len(safe), 255)
            self.assertTrue(safe.strip())  # Should not be empty
    
    def test_constant_time_compare(self):
        """Test constant-time comparison."""
        data1 = b"secret123"
        data2 = b"secret123"
        data3 = b"secret124"
        data4 = b"different_length"
        
        self.assertTrue(constant_time_compare(data1, data2))
        self.assertFalse(constant_time_compare(data1, data3))
        self.assertFalse(constant_time_compare(data1, data4))


class TestCrypto(unittest.TestCase):
    """Test cryptographic operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.crypto = FileEncryption()
        self.test_key = generate_key(32)
    
    def test_encryption_decryption(self):
        """Test file encryption and decryption."""
        test_data = b"This is a test file content with some data to encrypt."
        
        # Unlock crypto with test key
        self.crypto.unlock(self.test_key)
        
        # Encrypt data
        result = self.crypto.encrypt_file(test_data)
        self.assertIsNotNone(result.ciphertext)
        self.assertIsNotNone(result.nonce)
        self.assertIsNotNone(result.auth_tag)
        self.assertIsNotNone(result.encrypted_file_key)
        
        # Decrypt data
        decrypted = self.crypto.decrypt_file(
            result.ciphertext,
            result.nonce,
            result.auth_tag,
            result.encrypted_file_key
        )
        
        self.assertEqual(decrypted, test_data)
    
    def test_string_encryption(self):
        """Test string encryption and decryption."""
        test_string = "test_filename.txt"
        
        self.crypto.unlock(self.test_key)
        
        encrypted_data, nonce = self.crypto.encrypt_string(test_string)
        decrypted_string = self.crypto.decrypt_string(encrypted_data)
        
        self.assertEqual(decrypted_string, test_string)
    
    def test_locked_operations(self):
        """Test operations on locked crypto module."""
        test_data = b"test data"
        
        # Crypto should be locked by default
        self.assertTrue(self.crypto.is_locked())
        
        with self.assertRaises(RuntimeError):
            self.crypto.encrypt_file(test_data)
        
        with self.assertRaises(RuntimeError):
            self.crypto.decrypt_file(b"", b"", b"", b"")
        
        with self.assertRaises(RuntimeError):
            self.crypto.encrypt_string("test")
    
    def test_lock_unlock(self):
        """Test locking and unlocking crypto module."""
        self.assertTrue(self.crypto.is_locked())
        
        self.crypto.unlock(self.test_key)
        self.assertFalse(self.crypto.is_locked())
        
        self.crypto.lock()
        self.assertTrue(self.crypto.is_locked())


class TestAuth(unittest.TestCase):
    """Test authentication and key derivation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.auth = MasterPasswordAuth()
        self.test_password = "TestPassword123!"
    
    def test_password_hashing(self):
        """Test password hashing and verification."""
        # Hash password
        hash1 = self.auth.hash_password(self.test_password)
        hash2 = self.auth.hash_password(self.test_password)
        
        # Hashes should be different (due to random salt)
        self.assertNotEqual(hash1, hash2)
        
        # Both should verify correctly
        self.assertTrue(self.auth.verify_password(self.test_password, hash1))
        self.assertTrue(self.auth.verify_password(self.test_password, hash2))
        
        # Wrong password should fail
        self.assertFalse(self.auth.verify_password("WrongPassword", hash1))
    
    def test_key_derivation(self):
        """Test vault key derivation."""
        salt = generate_salt(32)
        
        key1 = self.auth.derive_vault_key(self.test_password, salt)
        key2 = self.auth.derive_vault_key(self.test_password, salt)
        
        # Same password and salt should produce same key
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)
        
        # Different salt should produce different key
        salt2 = generate_salt(32)
        key3 = self.auth.derive_vault_key(self.test_password, salt2)
        self.assertNotEqual(key1, key3)
    
    def test_password_validation(self):
        """Test password strength validation."""
        weak_passwords = [
            "short",
            "nouppercase123!",
            "NOLOWERCASE123!",
            "NoDigitsHere!",
            "NoSpecialChars123",
            "password123!"  # Common pattern
        ]
        
        for weak in weak_passwords:
            is_valid, _ = self.auth.validate_password_strength(weak)
            self.assertFalse(is_valid, f"Password should be invalid: {weak}")
        
        strong_password = "StrongPassword123!@#"
        is_valid, _ = self.auth.validate_password_strength(strong_password)
        self.assertTrue(is_valid)
    
    def test_secure_session(self):
        """Test secure session management."""
        session = SecureSession(self.auth)
        salt = generate_salt(32)
        
        self.assertFalse(session.is_active())
        
        vault_key = session.start_session(self.test_password, salt)
        self.assertTrue(session.is_active())
        self.assertEqual(vault_key, session.get_vault_key())
        
        session.end_session()
        self.assertFalse(session.is_active())
        
        with self.assertRaises(RuntimeError):
            session.get_vault_key()


class TestDatabase(unittest.TestCase):
    """Test database operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.temp_dir / "test.db"
        self.db = VaultDatabase(self.db_path)
        
        self.test_password_hash = "test_hash"
        self.test_salt = generate_salt(32)
    
    def tearDown(self):
        """Clean up test fixtures."""
        self.db.disconnect()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_database_initialization(self):
        """Test database initialization."""
        with self.db:
            self.db.initialize_database(self.test_password_hash, self.test_salt)
            
            # Check vault config
            config = self.db.get_vault_config()
            self.assertEqual(config.password_hash, self.test_password_hash)
            self.assertEqual(config.salt, self.test_salt)
            self.assertIsInstance(config.settings, dict)
    
    def test_file_operations(self):
        """Test file record operations."""
        with self.db:
            self.db.initialize_database(self.test_password_hash, self.test_salt)
            
            # Add file record
            file_id = self.db.add_file(
                encrypted_filename=b"encrypted_name",
                original_size=1024,
                encrypted_size=1100,
                encrypted_file_key=b"encrypted_key",
                nonce=b"test_nonce12",
                auth_tag=b"test_auth_tag123",
                integrity_hash="test_hash"
            )
            
            self.assertIsInstance(file_id, int)
            
            # Retrieve file record
            file_record = self.db.get_file_by_filename(b"encrypted_name")
            self.assertIsNotNone(file_record)
            self.assertEqual(file_record.id, file_id)
            self.assertEqual(file_record.original_size, 1024)
            self.assertEqual(file_record.encrypted_size, 1100)
            
            # List all files
            all_files = self.db.get_all_files()
            self.assertEqual(len(all_files), 1)
            self.assertEqual(all_files[0].id, file_id)
            
            # Delete file
            deleted = self.db.delete_file(file_id)
            self.assertTrue(deleted)
            
            # Should not find deleted file
            file_record = self.db.get_file_by_filename(b"encrypted_name")
            self.assertIsNone(file_record)
    
    def test_database_stats(self):
        """Test database statistics."""
        with self.db:
            self.db.initialize_database(self.test_password_hash, self.test_salt)
            
            stats = self.db.get_database_stats()
            self.assertEqual(stats['file_count'], 0)
            self.assertEqual(stats['total_original_size'], 0)
            
            # Add a file and check stats again
            self.db.add_file(
                encrypted_filename=b"test_file",
                original_size=2048,
                encrypted_size=2200,
                encrypted_file_key=b"key",
                nonce=b"nonce1234567",
                auth_tag=b"tag1234567890123",
                integrity_hash="hash"
            )
            
            stats = self.db.get_database_stats()
            self.assertEqual(stats['file_count'], 1)
            self.assertEqual(stats['total_original_size'], 2048)
            self.assertEqual(stats['total_encrypted_size'], 2200)


class TestVaultManager(unittest.TestCase):
    """Test vault manager operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.vault = VaultManager(self.temp_dir)
        self.test_password = "TestVaultPassword123!"
    
    def tearDown(self):
        """Clean up test fixtures."""
        try:
            self.vault.lock_vault()
        except:
            pass
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('auth.MasterPasswordAuth.create_master_password')
    def test_vault_initialization(self, mock_create_password):
        """Test vault initialization."""
        mock_create_password.return_value = (self.test_password, "hashed_password")
        
        self.assertFalse(self.vault.is_initialized())
        
        self.vault.initialize_vault()
        
        self.assertTrue(self.vault.is_initialized())
        self.assertTrue(self.vault.db_path.exists())
        self.assertTrue(self.vault.vault_file_dir.exists())
    
    @patch('auth.MasterPasswordAuth.authenticate_user')
    @patch('auth.MasterPasswordAuth.create_master_password')
    def test_vault_unlock_lock(self, mock_create_password, mock_authenticate):
        """Test vault unlock and lock operations."""
        # Setup mocks
        mock_create_password.return_value = (self.test_password, "hashed_password")
        mock_authenticate.return_value = self.test_password
        
        # Initialize vault
        self.vault.initialize_vault()
        
        # Test unlock
        self.assertTrue(self.vault.crypto.is_locked())
        self.vault.unlock_vault()
        self.assertFalse(self.vault.crypto.is_locked())
        
        # Test lock
        self.vault.lock_vault()
        self.assertTrue(self.vault.crypto.is_locked())
    
    @patch('auth.MasterPasswordAuth.authenticate_user')
    @patch('auth.MasterPasswordAuth.create_master_password')
    def test_file_operations(self, mock_create_password, mock_authenticate):
        """Test file add, list, get, and remove operations."""
        # Setup mocks
        mock_create_password.return_value = (self.test_password, "hashed_password")
        mock_authenticate.return_value = self.test_password
        
        # Initialize and unlock vault
        self.vault.initialize_vault()
        self.vault.unlock_vault()
        
        # Create test file
        test_file_content = b"This is test file content for vault operations."
        test_file = self.temp_dir / "test_file.txt"
        test_file.write_bytes(test_file_content)
        
        # Add file to vault
        self.vault.add_file(str(test_file))
        
        # List files
        files = self.vault.list_files()
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]['filename'], 'test_file.txt')
        self.assertEqual(files[0]['size'], len(test_file_content))
        
        # Get file from vault
        output_file = self.temp_dir / "retrieved_file.txt"
        self.vault.get_file('test_file.txt', str(output_file))
        
        # Verify retrieved file content
        retrieved_content = output_file.read_bytes()
        self.assertEqual(retrieved_content, test_file_content)
        
        # Remove file from vault
        self.vault.remove_file('test_file.txt')
        
        # Should not find file after removal
        files = self.vault.list_files()
        self.assertEqual(len(files), 0)
    
    def test_uninitialized_operations(self):
        """Test operations on uninitialized vault."""
        with self.assertRaises(VaultNotInitializedError):
            self.vault.unlock_vault()
        
        with self.assertRaises(VaultNotInitializedError):
            self.vault.add_file("nonexistent.txt")
        
        with self.assertRaises(VaultNotInitializedError):
            self.vault.list_files()
    
    @patch('auth.MasterPasswordAuth.create_master_password')
    def test_locked_operations(self, mock_create_password):
        """Test operations on locked vault."""
        mock_create_password.return_value = (self.test_password, "hashed_password")
        
        self.vault.initialize_vault()
        
        # Vault should be locked after initialization
        with self.assertRaises(VaultLockedError):
            self.vault.add_file("nonexistent.txt")
        
        with self.assertRaises(VaultLockedError):
            self.vault.list_files()
        
        with self.assertRaises(VaultLockedError):
            self.vault.get_file("nonexistent.txt", "/tmp/out")
    
    @patch('auth.MasterPasswordAuth.authenticate_user')
    @patch('auth.MasterPasswordAuth.create_master_password')
    def test_vault_status(self, mock_create_password, mock_authenticate):
        """Test vault status reporting."""
        # Test uninitialized status
        status = self.vault.get_vault_status()
        self.assertFalse(status['initialized'])
        self.assertTrue(status['locked'])
        
        # Initialize vault
        mock_create_password.return_value = (self.test_password, "hashed_password")
        self.vault.initialize_vault()
        
        status = self.vault.get_vault_status()
        self.assertTrue(status['initialized'])
        self.assertTrue(status['locked'])
        self.assertEqual(status['file_count'], 0)
        
        # Unlock vault
        mock_authenticate.return_value = self.test_password
        self.vault.unlock_vault()
        
        status = self.vault.get_vault_status()
        self.assertTrue(status['initialized'])
        self.assertFalse(status['locked'])
        self.assertTrue(status['session_info']['active'])


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.vault = VaultManager(self.temp_dir)
        self.test_password = "IntegrationTestPassword123!"
    
    def tearDown(self):
        """Clean up test fixtures."""
        try:
            self.vault.lock_vault()
        except:
            pass
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('auth.MasterPasswordAuth.create_master_password')
    @patch('auth.MasterPasswordAuth.authenticate_user')
    def test_complete_workflow(self, mock_authenticate, mock_create_password):
        """Test a complete vault workflow."""
        # Setup mocks
        mock_create_password.return_value = (self.test_password, "hashed_password")
        mock_authenticate.return_value = self.test_password
        
        # 1. Initialize vault
        self.vault.initialize_vault()
        self.assertTrue(self.vault.is_initialized())
        
        # 2. Unlock vault
        self.vault.unlock_vault()
        self.assertFalse(self.vault.crypto.is_locked())
        
        # 3. Create and add multiple test files
        test_files = {
            'document.txt': b'This is a text document.',
            'image.jpg': b'\xff\xd8\xff\xe0' + b'fake jpeg data' * 100,
            'config.json': b'{"setting": "value", "number": 42}'
        }
        
        for filename, content in test_files.items():
            test_file = self.temp_dir / filename
            test_file.write_bytes(content)
            self.vault.add_file(str(test_file))
        
        # 4. List files and verify
        files = self.vault.list_files()
        self.assertEqual(len(files), 3)
        filenames = {f['filename'] for f in files}
        self.assertEqual(filenames, set(test_files.keys()))
        
        # 5. Retrieve and verify each file
        for filename, expected_content in test_files.items():
            output_file = self.temp_dir / f'retrieved_{filename}'
            self.vault.get_file(filename, str(output_file))
            
            actual_content = output_file.read_bytes()
            self.assertEqual(actual_content, expected_content)
        
        # 6. Check vault status
        status = self.vault.get_vault_status()
        self.assertTrue(status['initialized'])
        self.assertFalse(status['locked'])
        self.assertEqual(status['file_count'], 3)
        
        # 7. Remove one file
        self.vault.remove_file('document.txt')
        files = self.vault.list_files()
        self.assertEqual(len(files), 2)
        
        # 8. Lock vault
        self.vault.lock_vault()
        self.assertTrue(self.vault.crypto.is_locked())
        
        # 9. Unlock again and verify files are still there
        self.vault.unlock_vault()
        files = self.vault.list_files()
        self.assertEqual(len(files), 2)
        
        # 10. Verify integrity
        integrity_results = self.vault.verify_vault_integrity()
        self.assertTrue(integrity_results['database_ok'])
        self.assertEqual(integrity_results['files_ok'], 2)
        self.assertEqual(len(integrity_results['corrupted_files']), 0)


def run_tests():
    """Run all tests with detailed output."""
    # Create test suite
    test_classes = [
        TestUtils,
        TestCrypto,
        TestAuth,
        TestDatabase,
        TestVaultManager,
        TestIntegration
    ]
    
    suite = unittest.TestSuite()
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(
        verbosity=2,
        failfast=False,
        buffer=True
    )
    
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {(result.testsRun - len(result.failures) - len(result.errors))/result.testsRun*100:.1f}%")
    
    if result.failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            print(f"  {test}: {traceback}")
    
    if result.errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            print(f"  {test}: {traceback}")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)