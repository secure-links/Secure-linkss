"""
Advanced Anti-Bot Protection System
Sophisticated multi-layered protection against automated traffic
"""

import hashlib
import hmac
import time
import json
import random
import string
import base64
from functools import wraps
from flask import request, jsonify, session, current_app
from datetime import datetime, timedelta
import ipaddress
import re
from urllib.parse import urlparse
import secrets

class AdvancedAntiBotProtection:
    def __init__(self, app=None):
        self.app = app
        self.blocked_ips = set()
        self.suspicious_ips = {}
        self.rate_limits = {}
        self.fingerprints = {}
        self.challenge_cache = {}
        
        # Bot detection patterns
        self.bot_user_agents = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests',
            'scrapy', 'selenium', 'phantomjs', 'headless', 'automation', 'test',
            'monitor', 'check', 'scan', 'probe', 'fetch', 'http', 'client',
            'library', 'framework', 'tool', 'script', 'api', 'service'
        ]
        
        # Suspicious patterns
        self.suspicious_patterns = [
            r'(?i)(bot|crawler|spider|scraper)',
            r'(?i)(curl|wget|python|java|go|rust)',
            r'(?i)(headless|phantom|selenium)',
            r'(?i)(automation|test|monitor)',
            r'(?i)(scan|probe|check|fetch)'
        ]
        
        # Known bot IP ranges (simplified)
        self.bot_ip_ranges = [
            '66.249.64.0/19',  # Google
            '157.55.39.0/24',  # Bing
            '40.77.167.0/24',  # Bing
            '207.46.13.0/24',  # Bing
            '199.30.24.0/24',  # Facebook
            '173.252.64.0/18', # Facebook
        ]
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        self.app = app
        app.before_request(self.before_request_handler)
    
    def generate_challenge_token(self, ip_address):
        """Generate a unique challenge token for browser verification"""
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        data = f"{ip_address}:{timestamp}:{nonce}"
        
        # Create HMAC signature
        secret_key = current_app.config.get('SECRET_KEY', 'default_secret')
        signature = hmac.new(
            secret_key.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        token = base64.b64encode(f"{data}:{signature}".encode()).decode()
        return token
    
    def verify_challenge_token(self, token, ip_address, max_age=300):
        """Verify challenge token validity"""
        try:
            decoded = base64.b64decode(token.encode()).decode()
            parts = decoded.split(':')
            
            if len(parts) != 4:
                return False
            
            token_ip, timestamp, nonce, signature = parts
            
            # Verify IP matches
            if token_ip != ip_address:
                return False
            
            # Verify timestamp (not expired)
            if int(time.time()) - int(timestamp) > max_age:
                return False
            
            # Verify signature
            data = f"{token_ip}:{timestamp}:{nonce}"
            secret_key = current_app.config.get('SECRET_KEY', 'default_secret')
            expected_signature = hmac.new(
                secret_key.encode(),
                data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception:
            return False
    
    def get_client_ip(self):
        """Get real client IP address"""
        # Check for forwarded headers (common in proxy setups)
        forwarded_ips = request.headers.get('X-Forwarded-For', '').split(',')
        if forwarded_ips and forwarded_ips[0].strip():
            return forwarded_ips[0].strip()
        
        # Check other common headers
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        # Fallback to remote address
        return request.remote_addr or '127.0.0.1'
    
    def is_bot_user_agent(self, user_agent):
        """Check if user agent indicates a bot"""
        if not user_agent:
            return True
        
        user_agent_lower = user_agent.lower()
        
        # Check against known bot patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, user_agent):
                return True
        
        # Check against bot keywords
        for keyword in self.bot_user_agents:
            if keyword in user_agent_lower:
                return True
        
        return False
    
    def is_bot_ip(self, ip_address):
        """Check if IP belongs to known bot networks"""
        try:
            ip = ipaddress.ip_address(ip_address)
            for cidr in self.bot_ip_ranges:
                if ip in ipaddress.ip_network(cidr):
                    return True
        except ValueError:
            pass
        return False
    
    def check_rate_limit(self, ip_address, max_requests=10, window=60):
        """Check if IP is exceeding rate limits"""
        current_time = time.time()
        
        if ip_address not in self.rate_limits:
            self.rate_limits[ip_address] = []
        
        # Clean old requests
        self.rate_limits[ip_address] = [
            req_time for req_time in self.rate_limits[ip_address]
            if current_time - req_time < window
        ]
        
        # Add current request
        self.rate_limits[ip_address].append(current_time)
        
        return len(self.rate_limits[ip_address]) > max_requests
    
    def generate_browser_fingerprint(self):
        """Generate fingerprint challenge for browser verification"""
        challenge_id = secrets.token_hex(8)
        
        # JavaScript challenge that only browsers can solve
        challenge_script = f"""
        <script>
        (function() {{
            var challenge = '{challenge_id}';
            var canvas = document.createElement('canvas');
            var ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('Browser verification: ' + challenge, 2, 2);
            
            var fingerprint = {{
                screen: screen.width + 'x' + screen.height,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                language: navigator.language,
                platform: navigator.platform,
                canvas: canvas.toDataURL(),
                timestamp: Date.now(),
                challenge: challenge
            }};
            
            // Send fingerprint back
            fetch('/api/verify-browser', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify(fingerprint)
            }}).then(function() {{
                window.location.reload();
            }});
        }})();
        </script>
        """
        
        self.challenge_cache[challenge_id] = {
            'created': time.time(),
            'ip': self.get_client_ip()
        }
        
        return challenge_script
    
    def analyze_request_behavior(self, ip_address):
        """Analyze request patterns for bot behavior"""
        suspicious_score = 0
        
        # Check headers
        headers = dict(request.headers)
        
        # Missing common browser headers
        if 'Accept' not in headers:
            suspicious_score += 20
        if 'Accept-Language' not in headers:
            suspicious_score += 15
        if 'Accept-Encoding' not in headers:
            suspicious_score += 15
        
        # Suspicious header values
        accept = headers.get('Accept', '')
        if accept == '*/*' or not accept:
            suspicious_score += 10
        
        # Check for automation tools
        user_agent = headers.get('User-Agent', '')
        if self.is_bot_user_agent(user_agent):
            suspicious_score += 30
        
        # Very short or very long user agent
        if len(user_agent) < 20 or len(user_agent) > 500:
            suspicious_score += 15
        
        # Missing referer on non-direct requests
        if not headers.get('Referer') and request.method == 'POST':
            suspicious_score += 10
        
        # Check request timing patterns
        if ip_address in self.suspicious_ips:
            last_requests = self.suspicious_ips[ip_address]
            current_time = time.time()
            
            # Too many requests in short time
            recent_requests = [t for t in last_requests if current_time - t < 10]
            if len(recent_requests) > 5:
                suspicious_score += 25
            
            # Too regular timing (bot-like)
            if len(last_requests) >= 3:
                intervals = [last_requests[i] - last_requests[i-1] for i in range(1, len(last_requests))]
                if len(set([round(interval, 1) for interval in intervals])) == 1:
                    suspicious_score += 20
        
        # Update tracking
        if ip_address not in self.suspicious_ips:
            self.suspicious_ips[ip_address] = []
        self.suspicious_ips[ip_address].append(time.time())
        
        # Keep only recent requests
        self.suspicious_ips[ip_address] = [
            t for t in self.suspicious_ips[ip_address]
            if time.time() - t < 300
        ]
        
        return suspicious_score
    
    def before_request_handler(self):
        """Main request handler for anti-bot protection"""
        ip_address = self.get_client_ip()
        
        # Skip protection for certain paths
        if request.path.startswith('/static/') or request.path.startswith('/api/verify-browser'):
            return
        
        # Check if IP is blocked
        if ip_address in self.blocked_ips:
            return jsonify({'error': 'Access denied'}), 403
        
        # Check rate limiting
        if self.check_rate_limit(ip_address, max_requests=20, window=60):
            self.blocked_ips.add(ip_address)
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        # Analyze request behavior
        suspicious_score = self.analyze_request_behavior(ip_address)
        
        # Check if browser verification is needed
        if suspicious_score > 50:
            # Check if already verified
            verification_token = session.get('browser_verified')
            if not verification_token or not self.verify_challenge_token(verification_token, ip_address):
                # Return browser challenge
                challenge_script = self.generate_browser_fingerprint()
                return f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Verification Required</title>
                    <meta name="robots" content="noindex, nofollow">
                </head>
                <body>
                    <h1>Browser Verification</h1>
                    <p>Please wait while we verify your browser...</p>
                    {challenge_script}
                </body>
                </html>
                """, 200
        
        # Log suspicious activity
        if suspicious_score > 30:
            current_app.logger.warning(f"Suspicious request from {ip_address}: score {suspicious_score}")

def require_human_verification(f):
    """Decorator to require human verification for sensitive endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip_address = request.remote_addr or '127.0.0.1'
        
        # Check if verified
        verification_token = session.get('browser_verified')
        if not verification_token:
            return jsonify({'error': 'Human verification required'}), 403
        
        # Verify token
        antibot = current_app.extensions.get('antibot')
        if not antibot or not antibot.verify_challenge_token(verification_token, ip_address):
            return jsonify({'error': 'Invalid verification'}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

