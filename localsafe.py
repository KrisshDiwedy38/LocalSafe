#!/usr/bin/env python3
"""
LocalSafe - Secure Local File Vault CLI

A command-line tool for encrypting and storing files locally with
strong cryptographic protection and automatic security features.
"""

import sys
import argparse
import signal
from pathlib import Path
from typing import NoReturn

from vault import VaultManager, VaultError, VaultNotInitializedError, VaultLockedError
from utils import get_vault_directory


def setup_signal_handlers(vault: VaultManager) -> None:
    """Setup signal handlers for graceful shutdown.
    
    Args:
        vault: The vault manager instance
    """
    def signal_handler(signum, frame):
        print("\nReceived interrupt signal. Locking vault...")
        try:
            if not vault.crypto.is_locked():
                vault.lock_vault()
        except:
            pass  # Best effort cleanup
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def format_size(size_bytes: int) -> str:
    """Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def format_duration(seconds: int) -> str:
    """Format duration in human-readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"


def cmd_init(args, vault: VaultManager) -> None:
    """Initialize a new vault.
    
    Args:
        args: Command arguments
        vault: Vault manager instance
    """
    try:
        vault.initialize_vault()
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_unlock(args, vault: VaultManager) -> None:
    """Unlock the vault.
    
    Args:
        args: Command arguments
        vault: Vault manager instance
    """
    try:
        vault.unlock_vault()
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_lock(args, vault: VaultManager) -> None:
    """Lock the vault.
    
    Args:
        args: Command arguments
        vault: Vault manager instance
    """
    try:
        if vault.crypto.is_locked():
            print("Vault is already locked.")
        else:
            vault.lock_vault()
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_add(args, vault: VaultManager) -> None:
    """Add a file to the vault.
    
    Args:
        args: Command arguments
        vault: Vault manager instance
    """
    try:
        vault.add_file(args.file)
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_get(args, vault: VaultManager) -> None:
    """Retrieve a file from the vault.
    
    Args:
        args: Command arguments
        vault: Vault manager instance
    """
    try:
        # Default output path if not specified
        output_path = args.output or args.filename
        vault.get_file(args.filename, output_path)
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_list(args, vault: VaultManager) -> None:
    """List files in the vault.
    
    Args:
        args: Command arguments
        vault: Vault manager instance
    """
    try:
        files = vault.list_files()
        
        if not files:
            print("No files in vault.")
            return
        
        if args.long:
            # Long format with detailed information
            print(f"{'ID':<4} {'Filename':<30} {'Size':<10} {'Encrypted':<10} {'Created':<20}")
            print("-" * 80)
            
            for file_info in files:
                size_str = format_size(file_info['size'])
                enc_size_str = format_size(file_info['encrypted_size'])
                created = file_info['created_at'][:19].replace('T', ' ')  # Format datetime
                
                print(f"{file_info['id']:<4} {file_info['filename']:<30} "
                      f"{size_str:<10} {enc_size_str:<10} {created:<20}")
        else:
            # Simple format
            for file_info in files:
                print(file_info['filename'])
                
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_remove(args, vault: VaultManager) -> None:
    """Remove a file from the vault.
    
    Args:
        args: Command arguments
        vault: Vault manager instance
    """
    try:
        # Confirm deletion unless --force is used
        if not args.force:
            response = input(f"Are you sure you want to remove '{args.filename}'? (y/N): ")
            if response.lower() != 'y':
                print("Operation cancelled.")
                return
        
        vault.remove_file(args.filename)
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_status(args, vault: VaultManager) -> None:
    """Show vault status and statistics.
    
    Args:
        args: Command arguments
        vault: Vault manager instance
    """
    try:
        status = vault.get_vault_status()
        
        print("Vault Status:")
        print(f"  Initialized: {'Yes' if status['initialized'] else 'No'}")
        print(f"  Locked: {'Yes' if status['locked'] else 'No'}")
        print(f"  Location: {status['vault_directory']}")
        
        if 'error' in status:
            print(f"  Error: {status['error']}")
        
        if status['initialized'] and 'file_count' in status:
            print(f"\nStatistics:")
            print(f"  Files: {status['file_count']}")
            print(f"  Total size (original): {format_size(status['total_original_size'])}")
            print(f"  Total size (encrypted): {format_size(status['total_encrypted_size'])}")
            print(f"  Database size: {format_size(status['database_size'])}")
        
        # Show session info if unlocked
        session_info = status.get('session_info', {})
        if session_info.get('active'):
            print(f"\nSession:")
            print(f"  Duration: {format_duration(session_info['duration'])}")
            print(f"  Activities: {session_info['activity_count']}")
            
            time_until_lock = session_info.get('time_until_lock')
            if time_until_lock is not None:
                if time_until_lock > 0:
                    print(f"  Auto-lock in: {format_duration(time_until_lock)}")
                else:
                    print(f"  Auto-lock: Triggered")
        
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_settings(args, vault: VaultManager) -> None:
    """Manage vault settings.
    
    Args:
        args: Command arguments
        vault: Vault manager instance
    """
    try:
        if args.auto_lock_timeout is not None:
            settings = {'auto_lock_timeout': args.auto_lock_timeout}
            vault.update_vault_settings(settings)
            print(f"Auto-lock timeout set to {args.auto_lock_timeout} seconds")
        
        elif args.max_file_size is not None:
            settings = {'max_file_size': args.max_file_size}
            vault.update_vault_settings(settings)
            print(f"Max file size set to {format_size(args.max_file_size)}")
        
        else:
            # Show current settings
            status = vault.get_vault_status()
            if not status['initialized']:
                print("Vault is not initialized.")
                return
            
            with vault.database:
                config = vault.database.get_vault_config()
                settings = config.settings
                
                print("Current Settings:")
                print(f"  Auto-lock timeout: {settings.get('auto_lock_timeout', 300)} seconds")
                print(f"  Max file size: {format_size(settings.get('max_file_size', 100*1024*1024))}")
                print(f"  Compression: {'Enabled' if settings.get('compression_enabled', True) else 'Disabled'}")
                print(f"  Version: {settings.get('version', '1.0')}")
        
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_verify(args, vault: VaultManager) -> None:
    """Verify vault integrity.
    
    Args:
        args: Command arguments
        vault: Vault manager instance
    """
    try:
        print("Verifying vault integrity...")
        results = vault.verify_vault_integrity()
        
        print(f"Database integrity: {'OK' if results['database_ok'] else 'FAILED'}")
        
        if results['files_checked'] > 0:
            print(f"Files checked: {results['files_checked']}")
            print(f"Files OK: {results['files_ok']}")
            
            if results['corrupted_files']:
                print(f"Corrupted files: {len(results['corrupted_files'])}")
                for corrupted in results['corrupted_files']:
                    print(f"  - {corrupted}")
            
            if results['missing_files']:
                print(f"Missing files: {len(results['missing_files'])}")
                for missing in results['missing_files']:
                    print(f"  - {missing}")
        
        if results['errors']:
            print("Errors:")
            for error in results['errors']:
                print(f"  - {error}")
        
        if not results['database_ok'] or results['corrupted_files'] or results['missing_files']:
            print("\nWarning: Vault integrity issues detected!")
            sys.exit(1)
        else:
            print("\nVault integrity verification completed successfully.")
        
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog='localsafe',
        description='LocalSafe - Secure Local File Vault',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  localsafe init                    # Initialize new vault
  localsafe unlock                  # Unlock vault
  localsafe add document.pdf        # Add file to vault
  localsafe get document.pdf        # Retrieve file from vault
  localsafe get document.pdf -o /tmp/doc.pdf  # Retrieve to specific path
  localsafe list                    # List files in vault
  localsafe list -l                 # List files with details
  localsafe remove document.pdf     # Remove file from vault
  localsafe lock                    # Lock vault
  localsafe status                  # Show vault status
        """
    )
    
    parser.add_argument(
        '--vault-dir',
        type=Path,
        help='Custom vault directory (default: ~/.localsafe)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    subparsers.add_parser('init', help='Initialize a new vault')
    
    # Unlock command
    subparsers.add_parser('unlock', help='Unlock the vault')
    
    # Lock command
    subparsers.add_parser('lock', help='Lock the vault')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add a file to the vault')
    add_parser.add_argument('file', help='File to add to vault')
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Retrieve a file from the vault')
    get_parser.add_argument('filename', help='Name of file to retrieve')
    get_parser.add_argument('-o', '--output', help='Output file path')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List files in the vault')
    list_parser.add_argument('-l', '--long', action='store_true', 
                           help='Show detailed information')
    
    # Remove command
    remove_parser = subparsers.add_parser('remove', help='Remove a file from the vault')
    remove_parser.add_argument('filename', help='Name of file to remove')
    remove_parser.add_argument('-f', '--force', action='store_true',
                             help='Remove without confirmation')
    
    # Status command
    subparsers.add_parser('status', help='Show vault status and statistics')
    
    # Settings command
    settings_parser = subparsers.add_parser('settings', help='Manage vault settings')
    settings_parser.add_argument('--auto-lock-timeout', type=int,
                               help='Set auto-lock timeout in seconds')
    settings_parser.add_argument('--max-file-size', type=int,
                               help='Set maximum file size in bytes')
    
    # Verify command
    subparsers.add_parser('verify', help='Verify vault integrity')
    
    return parser


def main() -> NoReturn:
    """Main entry point for the LocalSafe CLI."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Initialize vault manager
    vault = VaultManager(args.vault_dir)
    
    # Setup signal handlers for graceful shutdown
    setup_signal_handlers(vault)
    
    # Command dispatch table
    commands = {
        'init': cmd_init,
        'unlock': cmd_unlock,
        'lock': cmd_lock,
        'add': cmd_add,
        'get': cmd_get,
        'list': cmd_list,
        'remove': cmd_remove,
        'status': cmd_status,
        'settings': cmd_settings,
        'verify': cmd_verify
    }
    
    # Execute command
    try:
        command_func = commands.get(args.command)
        if command_func:
            command_func(args, vault)
        else:
            print(f"Unknown command: {args.command}", file=sys.stderr)
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)
    
    finally:
        # Ensure cleanup
        try:
            if not vault.crypto.is_locked():
                vault.lock_vault()
        except:
            pass  # Best effort cleanup


if __name__ == '__main__':
    main()