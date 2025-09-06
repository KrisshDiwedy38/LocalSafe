"""
LocalSafe - Auto-Lock Mechanism Module

This module implements automatic locking functionality with configurable
timeouts to enhance security by clearing sensitive data from memory.
"""

import time
import threading
from typing import Optional, Callable
from datetime import datetime, timedelta


class AutoLock:
    """Implements automatic locking with configurable timeout."""
    
    def __init__(self, lock_callback: Callable[[], None], timeout_seconds: int = 300):
        """Initialize the auto-lock mechanism.
        
        Args:
            lock_callback: Function to call when auto-lock triggers
            timeout_seconds: Inactivity timeout in seconds (default: 5 minutes)
        """
        self.lock_callback = lock_callback
        self.timeout_seconds = timeout_seconds
        self.last_activity: Optional[datetime] = None
        self.is_enabled = False
        self.is_locked = True
        self._lock = threading.RLock()
        self._timer: Optional[threading.Timer] = None
        self._stop_event = threading.Event()
    
    def enable(self) -> None:
        """Enable the auto-lock mechanism."""
        with self._lock:
            if not self.is_enabled:
                self.is_enabled = True
                self.is_locked = False
                self.update_activity()
                self._start_timer()
    
    def disable(self) -> None:
        """Disable the auto-lock mechanism."""
        with self._lock:
            self.is_enabled = False
            self._stop_timer()
    
    def lock_now(self) -> None:
        """Immediately trigger the lock."""
        with self._lock:
            if not self.is_locked:
                self.is_locked = True
                self._stop_timer()
                
                try:
                    self.lock_callback()
                except Exception as e:
                    # Log error but don't raise to avoid breaking the lock mechanism
                    print(f"Warning: Lock callback failed: {str(e)}")
    
    def unlock(self) -> None:
        """Unlock and reset the activity timer."""
        with self._lock:
            if self.is_locked:
                self.is_locked = False
                if self.is_enabled:
                    self.update_activity()
                    self._start_timer()
    
    def update_activity(self) -> None:
        """Update the last activity timestamp and reset the timer."""
        with self._lock:
            if not self.is_enabled or self.is_locked:
                return
            
            self.last_activity = datetime.now()
            
            # Reset the timer
            self._stop_timer()
            self._start_timer()
    
    def set_timeout(self, timeout_seconds: int) -> None:
        """Update the auto-lock timeout.
        
        Args:
            timeout_seconds: New timeout in seconds
        """
        with self._lock:
            self.timeout_seconds = max(60, timeout_seconds)  # Minimum 1 minute
            
            # Restart timer with new timeout if currently active
            if self.is_enabled and not self.is_locked:
                self._stop_timer()
                self._start_timer()
    
    def get_time_until_lock(self) -> Optional[int]:
        """Get the number of seconds until auto-lock triggers.
        
        Returns:
            Seconds until lock, or None if disabled/locked
        """
        with self._lock:
            if not self.is_enabled or self.is_locked or not self.last_activity:
                return None
            
            elapsed = (datetime.now() - self.last_activity).total_seconds()
            remaining = max(0, self.timeout_seconds - elapsed)
            
            return int(remaining)
    
    def is_active(self) -> bool:
        """Check if auto-lock is currently active (enabled and unlocked).
        
        Returns:
            True if active, False otherwise
        """
        with self._lock:
            return self.is_enabled and not self.is_locked
    
    def _start_timer(self) -> None:
        """Start the auto-lock timer (internal method)."""
        if self._timer is not None:
            self._stop_timer()
        
        self._timer = threading.Timer(self.timeout_seconds, self._timer_expired)
        self._timer.daemon = True
        self._timer.start()
    
    def _stop_timer(self) -> None:
        """Stop the auto-lock timer (internal method)."""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
    
    def _timer_expired(self) -> None:
        """Handle timer expiration (internal method)."""
        with self._lock:
            if self.is_enabled and not self.is_locked:
                self.lock_now()
    
    def __del__(self):
        """Cleanup when object is destroyed."""
        self.disable()


class SessionManager:
    """Manages secure sessions with activity tracking and auto-lock."""
    
    def __init__(self, auto_lock_timeout: int = 300):
        """Initialize the session manager.
        
        Args:
            auto_lock_timeout: Auto-lock timeout in seconds (default: 5 minutes)
        """
        self.auto_lock = AutoLock(self._on_auto_lock, auto_lock_timeout)
        self.session_start_time: Optional[datetime] = None
        self.activity_count = 0
        self._session_callbacks = []
        self._lock_callbacks = []
    
    def start_session(self) -> None:
        """Start a new secure session."""
        self.session_start_time = datetime.now()
        self.activity_count = 0
        self.auto_lock.unlock()
        self.auto_lock.enable()
        
        # Notify session start callbacks
        for callback in self._session_callbacks:
            try:
                callback('start')
            except Exception as e:
                print(f"Warning: Session callback failed: {str(e)}")
    
    def end_session(self) -> None:
        """End the current session."""
        self.auto_lock.disable()
        self.auto_lock.lock_now()
        self.session_start_time = None
        
        # Notify session end callbacks
        for callback in self._session_callbacks:
            try:
                callback('end')
            except Exception as e:
                print(f"Warning: Session callback failed: {str(e)}")
    
    def record_activity(self, activity_type: str = "general") -> None:
        """Record user activity to reset auto-lock timer.
        
        Args:
            activity_type: Type of activity (for logging/debugging)
        """
        self.activity_count += 1
        self.auto_lock.update_activity()
    
    def is_session_active(self) -> bool:
        """Check if a session is currently active.
        
        Returns:
            True if session is active, False otherwise
        """
        return self.session_start_time is not None and self.auto_lock.is_active()
    
    def get_session_info(self) -> dict:
        """Get information about the current session.
        
        Returns:
            Dictionary with session information
        """
        if not self.session_start_time:
            return {
                'active': False,
                'duration': 0,
                'activity_count': 0,
                'time_until_lock': None
            }
        
        duration = (datetime.now() - self.session_start_time).total_seconds()
        
        return {
            'active': self.is_session_active(),
            'duration': int(duration),
            'activity_count': self.activity_count,
            'time_until_lock': self.auto_lock.get_time_until_lock()
        }
    
    def extend_session(self, additional_seconds: int = 300) -> None:
        """Extend the current session timeout.
        
        Args:
            additional_seconds: Additional time to add (default: 5 minutes)
        """
        if self.is_session_active():
            current_timeout = self.auto_lock.timeout_seconds
            self.auto_lock.set_timeout(current_timeout + additional_seconds)
            self.record_activity("session_extended")
    
    def add_session_callback(self, callback: Callable[[str], None]) -> None:
        """Add a callback for session events.
        
        Args:
            callback: Function to call with 'start' or 'end' events
        """
        self._session_callbacks.append(callback)
    
    def add_lock_callback(self, callback: Callable[[], None]) -> None:
        """Add a callback for lock events.
        
        Args:
            callback: Function to call when auto-lock triggers
        """
        self._lock_callbacks.append(callback)
    
    def _on_auto_lock(self) -> None:
        """Handle auto-lock event (internal method)."""
        # Call all registered lock callbacks
        for callback in self._lock_callbacks:
            try:
                callback()
            except Exception as e:
                print(f"Warning: Lock callback failed: {str(e)}")


class InactivityMonitor:
    """Monitors system inactivity for enhanced security."""
    
    def __init__(self, session_manager: SessionManager, check_interval: int = 30):
        """Initialize the inactivity monitor.
        
        Args:
            session_manager: The session manager to monitor
            check_interval: How often to check inactivity (seconds)
        """
        self.session_manager = session_manager
        self.check_interval = check_interval
        self.is_monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
    
    def start_monitoring(self) -> None:
        """Start monitoring for inactivity."""
        if not self.is_monitoring:
            self.is_monitoring = True
            self._stop_event.clear()
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True
            )
            self._monitor_thread.start()
    
    def stop_monitoring(self) -> None:
        """Stop monitoring for inactivity."""
        if self.is_monitoring:
            self.is_monitoring = False
            self._stop_event.set()
            
            if self._monitor_thread and self._monitor_thread.is_alive():
                self._monitor_thread.join(timeout=1.0)
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop (internal method)."""
        while self.is_monitoring and not self._stop_event.is_set():
            try:
                # Check if session is still active
                if not self.session_manager.is_session_active():
                    break
                
                # Additional inactivity checks could be added here
                # For example: check for system idle time, screen lock, etc.
                
                # Wait for next check
                if self._stop_event.wait(self.check_interval):
                    break  # Stop event was set
                    
            except Exception as e:
                print(f"Warning: Inactivity monitor error: {str(e)}")
                break
    
    def __del__(self):
        """Cleanup when object is destroyed."""
        self.stop_monitoring()