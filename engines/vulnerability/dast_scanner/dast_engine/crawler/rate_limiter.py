"""
Rate limiter for polite crawling
"""

import time
from datetime import datetime
from threading import Lock


class RateLimiter:
    """
    Rate limiter to control request frequency
    Prevents overwhelming target servers
    """
    
    def __init__(self, requests_per_second: int = 10):
        """
        Initialize rate limiter
        
        Args:
            requests_per_second: Maximum requests allowed per second
        """
        self.rate = requests_per_second
        self.requests_this_second = 0
        self.current_second = None
        self.lock = Lock()
        self.total_requests = 0
        self.start_time = time.time()
    
    def wait_if_needed(self):
        """
        Wait if rate limit would be exceeded
        Call this before making each request
        """
        with self.lock:
            now = time.time()
            current_second = int(now)
            
            # New second, reset counter
            if current_second != self.current_second:
                self.current_second = current_second
                self.requests_this_second = 0
            
            # Check if we've hit the limit
            if self.requests_this_second >= self.rate:
                # Calculate time to wait
                next_second = current_second + 1
                wait_time = next_second - now
                
                if wait_time > 0:
                    time.sleep(wait_time)
                
                # Reset for new second
                self.current_second = int(time.time())
                self.requests_this_second = 0
            
            # Increment counter
            self.requests_this_second += 1
            self.total_requests += 1
    
    def get_stats(self) -> dict:
        """Get rate limiter statistics"""
        elapsed = time.time() - self.start_time
        avg_rate = self.total_requests / elapsed if elapsed > 0 else 0
        
        return {
            'total_requests': self.total_requests,
            'elapsed_seconds': round(elapsed, 2),
            'average_rate': round(avg_rate, 2),
            'configured_rate': self.rate
        }
    
    def reset(self):
        """Reset statistics"""
        with self.lock:
            self.requests_this_second = 0
            self.current_second = None
            self.total_requests = 0
            self.start_time = time.time()
