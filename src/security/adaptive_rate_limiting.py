"""
Adaptive Rate Limiting and Throttling System
In-house implementation for intelligent traffic management
"""

import time
import json
import hashlib
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading

class AdaptiveRateLimiter:
    def __init__(self):
        self.rate_limits = defaultdict(lambda: {
            'requests': deque(),
            'violations': 0,
            'last_violation': 0,
            'current_limit': 60,  # requests per minute
            'adaptive_factor': 1.0,
            'whitelist_score': 0
        })
        
        # Global rate limiting configuration
        self.global_config = {
            'base_limit': 60,           # Base requests per minute
            'burst_limit': 120,         # Maximum burst requests
            'window_size': 60,          # Time window in seconds
            'violation_threshold': 3,    # Violations before stricter limits
            'adaptive_enabled': True,    # Enable adaptive limiting
            'whitelist_threshold': 100   # Score needed for whitelisting
        }
        
        # Different limits for different endpoints
        self.endpoint_limits = {
            '/api/': {'base': 30, 'burst': 60},      # API endpoints
            '/create-link': {'base': 10, 'burst': 20}, # Link creation
            '/analytics': {'base': 20, 'burst': 40},   # Analytics
            '/admin': {'base': 5, 'burst': 10},        # Admin endpoints
            '/static/': {'base': 200, 'burst': 400},   # Static files
            '/': {'base': 60, 'burst': 120}            # General pages
        }
        
        # Adaptive factors based on behavior
        self.behavior_factors = {
            'legitimate_user': 1.5,      # 50% more requests allowed
            'suspicious_activity': 0.5,   # 50% fewer requests allowed
            'bot_detected': 0.1,         # 90% reduction
            'honeypot_triggered': 0.05,  # 95% reduction
            'verified_browser': 1.2      # 20% more requests allowed
        }
        
        # Lock for thread safety
        self._lock = threading.Lock()
        
        # Cleanup thread
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = time.time()
    
    def check_rate_limit(self, ip_address, endpoint='/', user_behavior=None):
        """Check if request should be rate limited"""
        with self._lock:
            current_time = time.time()
            
            # Perform cleanup if needed
            if current_time - self._last_cleanup > self._cleanup_interval:
                self._cleanup_old_entries()
                self._last_cleanup = current_time
            
            # Get or create rate limit data for this IP
            ip_data = self.rate_limits[ip_address]
            
            # Determine the appropriate limit for this endpoint
            endpoint_limit = self._get_endpoint_limit(endpoint)
            
            # Apply adaptive factors based on behavior
            if user_behavior:
                adaptive_limit = self._apply_adaptive_factors(
                    endpoint_limit, user_behavior, ip_data
                )
            else:
                adaptive_limit = endpoint_limit
            
            # Clean old requests from the window
            self._clean_request_window(ip_data, current_time)
            
            # Check if limit is exceeded
            current_requests = len(ip_data['requests'])
            
            if current_requests >= adaptive_limit:
                # Rate limit exceeded
                ip_data['violations'] += 1
                ip_data['last_violation'] = current_time
                
                # Apply stricter limits for repeat violators
                self._apply_violation_penalty(ip_data)
                
                return {
                    'allowed': False,
                    'limit_exceeded': True,
                    'current_requests': current_requests,
                    'limit': adaptive_limit,
                    'reset_time': current_time + self.global_config['window_size'],
                    'retry_after': self._calculate_retry_after(ip_data),
                    'violation_count': ip_data['violations']
                }
            
            # Request is allowed
            ip_data['requests'].append(current_time)
            
            # Update whitelist score for good behavior
            self._update_whitelist_score(ip_data, current_time)
            
            return {
                'allowed': True,
                'limit_exceeded': False,
                'current_requests': current_requests + 1,
                'limit': adaptive_limit,
                'remaining': adaptive_limit - current_requests - 1,
                'reset_time': current_time + self.global_config['window_size']
            }
    
    def _get_endpoint_limit(self, endpoint):
        """Get the appropriate rate limit for an endpoint"""
        # Find the most specific matching endpoint pattern
        for pattern, limits in self.endpoint_limits.items():
            if endpoint.startswith(pattern):
                return limits['base']
        
        # Default to global base limit
        return self.global_config['base_limit']
    
    def _apply_adaptive_factors(self, base_limit, user_behavior, ip_data):
        """Apply adaptive factors based on user behavior"""
        if not self.global_config['adaptive_enabled']:
            return base_limit
        
        adaptive_factor = 1.0
        
        # Apply behavior-based factors
        for behavior, factor in self.behavior_factors.items():
            if behavior in user_behavior and user_behavior[behavior]:
                adaptive_factor *= factor
        
        # Apply whitelist bonus
        if ip_data['whitelist_score'] >= self.global_config['whitelist_threshold']:
            adaptive_factor *= 2.0  # Double the limit for whitelisted IPs
        
        # Apply violation penalty
        if ip_data['violations'] > 0:
            violation_factor = max(0.1, 1.0 - (ip_data['violations'] * 0.2))
            adaptive_factor *= violation_factor
        
        # Calculate final limit
        final_limit = int(base_limit * adaptive_factor)
        
        # Ensure minimum limit
        return max(final_limit, 1)
    
    def _clean_request_window(self, ip_data, current_time):
        """Remove requests outside the time window"""
        window_start = current_time - self.global_config['window_size']
        
        # Remove old requests
        while ip_data['requests'] and ip_data['requests'][0] < window_start:
            ip_data['requests'].popleft()
    
    def _apply_violation_penalty(self, ip_data):
        """Apply penalties for rate limit violations"""
        violations = ip_data['violations']
        
        if violations >= self.global_config['violation_threshold']:
            # Reduce current limit for repeat violators
            penalty_factor = max(0.1, 1.0 - (violations * 0.1))
            ip_data['current_limit'] = int(
                self.global_config['base_limit'] * penalty_factor
            )
        
        # Reset violations after a period of good behavior
        current_time = time.time()
        if (current_time - ip_data['last_violation']) > 3600:  # 1 hour
            ip_data['violations'] = max(0, ip_data['violations'] - 1)
    
    def _calculate_retry_after(self, ip_data):
        """Calculate retry-after time based on violations"""
        base_retry = 60  # 1 minute base
        violations = ip_data['violations']
        
        # Exponential backoff for repeat violators
        retry_after = base_retry * (2 ** min(violations - 1, 5))  # Cap at 32x
        
        return min(retry_after, 3600)  # Maximum 1 hour
    
    def _update_whitelist_score(self, ip_data, current_time):
        """Update whitelist score for good behavior"""
        # Increase score for normal usage
        if len(ip_data['requests']) < (self.global_config['base_limit'] * 0.5):
            ip_data['whitelist_score'] += 1
        
        # Decrease score for violations
        if ip_data['violations'] > 0:
            ip_data['whitelist_score'] = max(0, ip_data['whitelist_score'] - 5)
        
        # Cap the score
        ip_data['whitelist_score'] = min(
            ip_data['whitelist_score'], 
            self.global_config['whitelist_threshold'] * 2
        )
    
    def _cleanup_old_entries(self):
        """Clean up old rate limiting entries"""
        current_time = time.time()
        cleanup_threshold = current_time - 3600  # 1 hour
        
        # Remove entries that haven't been active recently
        inactive_ips = []
        for ip_address, ip_data in self.rate_limits.items():
            if (not ip_data['requests'] or 
                ip_data['requests'][-1] < cleanup_threshold):
                inactive_ips.append(ip_address)
        
        for ip_address in inactive_ips:
            del self.rate_limits[ip_address]
    
    def add_to_whitelist(self, ip_address):
        """Add IP to whitelist"""
        with self._lock:
            ip_data = self.rate_limits[ip_address]
            ip_data['whitelist_score'] = self.global_config['whitelist_threshold']
            ip_data['violations'] = 0
    
    def add_to_blacklist(self, ip_address):
        """Add IP to blacklist (severe rate limiting)"""
        with self._lock:
            ip_data = self.rate_limits[ip_address]
            ip_data['violations'] = 10  # High violation count
            ip_data['whitelist_score'] = 0
            ip_data['current_limit'] = 1  # Very restrictive
    
    def get_ip_status(self, ip_address):
        """Get current status for an IP address"""
        with self._lock:
            if ip_address not in self.rate_limits:
                return {
                    'requests_in_window': 0,
                    'violations': 0,
                    'whitelist_score': 0,
                    'current_limit': self.global_config['base_limit'],
                    'status': 'new'
                }
            
            ip_data = self.rate_limits[ip_address]
            current_time = time.time()
            
            # Clean the window first
            self._clean_request_window(ip_data, current_time)
            
            # Determine status
            status = 'normal'
            if ip_data['whitelist_score'] >= self.global_config['whitelist_threshold']:
                status = 'whitelisted'
            elif ip_data['violations'] >= self.global_config['violation_threshold']:
                status = 'restricted'
            
            return {
                'requests_in_window': len(ip_data['requests']),
                'violations': ip_data['violations'],
                'whitelist_score': ip_data['whitelist_score'],
                'current_limit': ip_data['current_limit'],
                'status': status,
                'last_violation': ip_data['last_violation']
            }
    
    def update_global_config(self, new_config):
        """Update global rate limiting configuration"""
        with self._lock:
            self.global_config.update(new_config)
    
    def update_endpoint_limits(self, endpoint, limits):
        """Update limits for a specific endpoint"""
        with self._lock:
            self.endpoint_limits[endpoint] = limits
    
    def get_global_statistics(self):
        """Get global rate limiting statistics"""
        with self._lock:
            current_time = time.time()
            
            total_ips = len(self.rate_limits)
            active_ips = 0
            whitelisted_ips = 0
            restricted_ips = 0
            total_requests = 0
            total_violations = 0
            
            for ip_data in self.rate_limits.values():
                # Clean the window for accurate counts
                self._clean_request_window(ip_data, current_time)
                
                if ip_data['requests']:
                    active_ips += 1
                
                if ip_data['whitelist_score'] >= self.global_config['whitelist_threshold']:
                    whitelisted_ips += 1
                
                if ip_data['violations'] >= self.global_config['violation_threshold']:
                    restricted_ips += 1
                
                total_requests += len(ip_data['requests'])
                total_violations += ip_data['violations']
            
            return {
                'total_tracked_ips': total_ips,
                'active_ips': active_ips,
                'whitelisted_ips': whitelisted_ips,
                'restricted_ips': restricted_ips,
                'total_requests_in_window': total_requests,
                'total_violations': total_violations,
                'global_config': self.global_config.copy(),
                'endpoint_limits': self.endpoint_limits.copy()
            }
    
    def create_rate_limit_response(self, limit_result):
        """Create HTTP response headers for rate limiting"""
        headers = {}
        
        if limit_result['allowed']:
            headers['X-RateLimit-Limit'] = str(limit_result['limit'])
            headers['X-RateLimit-Remaining'] = str(limit_result['remaining'])
            headers['X-RateLimit-Reset'] = str(int(limit_result['reset_time']))
        else:
            headers['X-RateLimit-Limit'] = str(limit_result['limit'])
            headers['X-RateLimit-Remaining'] = '0'
            headers['X-RateLimit-Reset'] = str(int(limit_result['reset_time']))
            headers['Retry-After'] = str(limit_result['retry_after'])
        
        return headers
    
    def is_burst_detected(self, ip_address, time_window=10):
        """Detect burst traffic patterns"""
        with self._lock:
            if ip_address not in self.rate_limits:
                return False
            
            ip_data = self.rate_limits[ip_address]
            current_time = time.time()
            
            # Count requests in the last time_window seconds
            burst_start = current_time - time_window
            burst_requests = sum(
                1 for req_time in ip_data['requests']
                if req_time >= burst_start
            )
            
            # Get burst limit for comparison
            burst_limit = self.global_config['burst_limit']
            
            return burst_requests > burst_limit
    
    def apply_emergency_limits(self, duration=300):
        """Apply emergency rate limits globally"""
        with self._lock:
            # Store original limits
            if not hasattr(self, '_original_limits'):
                self._original_limits = self.global_config.copy()
            
            # Apply emergency limits (much stricter)
            emergency_config = {
                'base_limit': 10,
                'burst_limit': 20,
                'violation_threshold': 1
            }
            
            self.global_config.update(emergency_config)
            
            # Set timer to restore original limits
            def restore_limits():
                time.sleep(duration)
                with self._lock:
                    if hasattr(self, '_original_limits'):
                        self.global_config.update(self._original_limits)
                        delattr(self, '_original_limits')
            
            import threading
            restore_thread = threading.Thread(target=restore_limits)
            restore_thread.daemon = True
            restore_thread.start()
    
    def get_rate_limit_middleware(self):
        """Get Flask middleware function for rate limiting"""
        def rate_limit_middleware():
            from flask import request, jsonify, g
            
            # Get client IP
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            if ip_address and ',' in ip_address:
                ip_address = ip_address.split(',')[0].strip()
            
            # Get endpoint
            endpoint = request.path
            
            # Get user behavior context (if available)
            user_behavior = getattr(g, 'user_behavior', {})
            
            # Check rate limit
            limit_result = self.check_rate_limit(ip_address, endpoint, user_behavior)
            
            # Store result in g for use by other components
            g.rate_limit_result = limit_result
            
            if not limit_result['allowed']:
                # Rate limit exceeded
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f"Too many requests. Try again in {limit_result['retry_after']} seconds.",
                    'retry_after': limit_result['retry_after']
                })
                response.status_code = 429
                
                # Add rate limit headers
                headers = self.create_rate_limit_response(limit_result)
                for header, value in headers.items():
                    response.headers[header] = value
                
                return response
            
            return None  # Allow request to continue
        
        return rate_limit_middleware

