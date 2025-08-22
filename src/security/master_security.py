"""
Master Security Coordinator
Safely integrates all anti-bot components without breaking existing functionality
"""

import time
import json
from flask import request, session, g, jsonify
from .antibot import AdvancedAntiBotProtection
from .ip_intelligence import IPIntelligenceEngine
from .behavioral_analysis import BehavioralAnalysisEngine
from .client_challenges import ClientChallengeEngine
from .honeypots import HoneypotEngine
from .advanced_fingerprinting import AdvancedFingerprintEngine
from .adaptive_rate_limiting import AdaptiveRateLimiter

class MasterSecurityCoordinator:
    def __init__(self, app=None, secret_key=None):
        self.app = app
        self.secret_key = secret_key or 'default_security_key'
        
        # Initialize all security components
        self.antibot = AdvancedAntiBotProtection()
        self.ip_intelligence = IPIntelligenceEngine()
        self.behavioral_analysis = BehavioralAnalysisEngine()
        self.client_challenges = ClientChallengeEngine(self.secret_key)
        self.honeypots = HoneypotEngine()
        self.fingerprinting = AdvancedFingerprintEngine()
        self.rate_limiter = AdaptiveRateLimiter()
        
        # Security configuration
        self.config = {
            'enabled': True,
            'strict_mode': False,  # Start in permissive mode
            'challenge_threshold': 70,  # Score threshold for challenges
            'block_threshold': 90,      # Score threshold for blocking
            'honeypot_enabled': True,
            'rate_limiting_enabled': True,
            'fingerprinting_enabled': True,
            'behavioral_analysis_enabled': True,
            'graceful_degradation': True  # Continue if components fail
        }
        
        # Statistics tracking
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'challenged_requests': 0,
            'honeypot_triggers': 0,
            'rate_limited_requests': 0,
            'start_time': time.time()
        }
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the security system with Flask app"""
        self.app = app
        
        # Register security middleware
        app.before_request(self.security_middleware)
        
        # Register security routes
        self.register_security_routes(app)
        
        # Register cleanup tasks
        self.register_cleanup_tasks(app)
    
    def security_middleware(self):
        """Main security middleware - runs before every request"""
        try:
            # Skip security for static files and certain paths
            if self._should_skip_security():
                return None
            
            # Get client information
            client_info = self._extract_client_info()
            
            # Update statistics
            self.stats['total_requests'] += 1
            
            # Phase 1: Rate Limiting (fastest check)
            if self.config['rate_limiting_enabled']:
                rate_result = self._check_rate_limiting(client_info)
                if rate_result and not rate_result['allowed']:
                    self.stats['rate_limited_requests'] += 1
                    return self._create_rate_limit_response(rate_result)
            
            # Phase 2: Honeypot Detection (immediate block)
            if self.config['honeypot_enabled']:
                honeypot_result = self._check_honeypots(client_info)
                if honeypot_result:
                    self.stats['honeypot_triggers'] += 1
                    return self._handle_honeypot_trigger(honeypot_result, client_info)
            
            # Phase 3: IP Intelligence (quick reputation check)
            ip_intelligence = self._analyze_ip_reputation(client_info)
            
            # Phase 4: Behavioral Analysis (if enabled)
            behavioral_score = 0
            if self.config['behavioral_analysis_enabled']:
                behavioral_result = self._analyze_behavior(client_info)
                behavioral_score = behavioral_result.get('anomaly_score', 0)
            
            # Phase 5: Fingerprinting (if enabled)
            fingerprint_score = 0
            if self.config['fingerprinting_enabled']:
                fingerprint_result = self._analyze_fingerprint(client_info)
                fingerprint_score = fingerprint_result.get('risk_score', 0)
            
            # Calculate combined threat score
            threat_score = self._calculate_threat_score(
                ip_intelligence, behavioral_score, fingerprint_score
            )
            
            # Store security context for use by other components
            g.security_context = {
                'threat_score': threat_score,
                'ip_intelligence': ip_intelligence,
                'behavioral_score': behavioral_score,
                'fingerprint_score': fingerprint_score,
                'client_info': client_info
            }
            
            # Decide action based on threat score
            if threat_score >= self.config['block_threshold']:
                self.stats['blocked_requests'] += 1
                return self._handle_high_threat(threat_score, client_info)
            elif threat_score >= self.config['challenge_threshold']:
                self.stats['challenged_requests'] += 1
                return self._handle_medium_threat(threat_score, client_info)
            
            # Request is allowed to proceed
            return None
            
        except Exception as e:
            # Graceful degradation - log error but allow request
            if self.config['graceful_degradation']:
                print(f"Security middleware error: {e}")
                return None
            else:
                return jsonify({'error': 'Security system error'}), 500
    
    def _should_skip_security(self):
        """Determine if security checks should be skipped"""
        skip_paths = [
            '/static/',
            '/favicon.ico',
            '/robots.txt',
            '/api/security/',  # Security API endpoints
            '/api/honeypot-trigger'  # Honeypot reporting
        ]
        
        path = request.path
        return any(path.startswith(skip_path) for skip_path in skip_paths)
    
    def _extract_client_info(self):
        """Extract client information from request"""
        return {
            'ip_address': self._get_client_ip(),
            'user_agent': request.headers.get('User-Agent', ''),
            'headers': dict(request.headers),
            'path': request.path,
            'method': request.method,
            'query_params': dict(request.args),
            'form_data': dict(request.form) if request.form else {},
            'cookies': dict(request.cookies),
            'timestamp': time.time(),
            'session_id': session.get('session_id', 'anonymous')
        }
    
    def _get_client_ip(self):
        """Get the real client IP address"""
        # Check for forwarded headers (common in production)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        return request.remote_addr
    
    def _check_rate_limiting(self, client_info):
        """Check rate limiting"""
        try:
            return self.rate_limiter.check_rate_limit(
                client_info['ip_address'],
                client_info['path'],
                getattr(g, 'user_behavior', {})
            )
        except Exception as e:
            if self.config['graceful_degradation']:
                print(f"Rate limiting error: {e}")
                return {'allowed': True}  # Allow on error
            raise
    
    def _check_honeypots(self, client_info):
        """Check for honeypot triggers"""
        try:
            # Check path-based honeypots
            if self.honeypots.check_honeypot_access(
                client_info['path'],
                client_info['ip_address'],
                client_info['user_agent'],
                client_info['headers']
            ):
                return {'type': 'path_honeypot', 'path': client_info['path']}
            
            # Check form-based honeypots
            if client_info['form_data']:
                triggered_traps = self.honeypots.check_hidden_field_submission(
                    client_info['form_data'],
                    client_info['ip_address']
                )
                if triggered_traps:
                    return {'type': 'form_honeypot', 'traps': triggered_traps}
            
            # Check cookie-based honeypots
            triggered_cookies = self.honeypots.check_trap_cookies(
                client_info['cookies'],
                client_info['ip_address']
            )
            if triggered_cookies:
                return {'type': 'cookie_honeypot', 'traps': triggered_cookies}
            
            return None
            
        except Exception as e:
            if self.config['graceful_degradation']:
                print(f"Honeypot check error: {e}")
                return None
            raise
    
    def _analyze_ip_reputation(self, client_info):
        """Analyze IP reputation"""
        try:
            return self.ip_intelligence.get_ip_intelligence(client_info['ip_address'])
        except Exception as e:
            if self.config['graceful_degradation']:
                print(f"IP intelligence error: {e}")
                return {'score': 0, 'action': 'allow'}
            raise
    
    def _analyze_behavior(self, client_info):
        """Analyze behavioral patterns"""
        try:
            return self.behavioral_analysis.analyze_request_behavior(
                client_info['session_id'],
                client_info
            )
        except Exception as e:
            if self.config['graceful_degradation']:
                print(f"Behavioral analysis error: {e}")
                return {'anomaly_score': 0}
            raise
    
    def _analyze_fingerprint(self, client_info):
        """Analyze browser fingerprint"""
        try:
            # For now, just analyze HTTP fingerprint
            # JS fingerprint would be collected separately
            http_fingerprint = self.fingerprinting.analyze_http_fingerprint(
                client_info['headers'],
                client_info['ip_address']
            )
            
            # Calculate risk score from HTTP analysis
            risk_score = 0
            if http_fingerprint['analysis']['user_agent']['is_suspicious']:
                risk_score += 30
            if http_fingerprint['analysis']['accept_headers']['is_suspicious']:
                risk_score += 20
            if http_fingerprint['analysis']['header_analysis']['is_suspicious']:
                risk_score += 15
            
            return {'risk_score': risk_score, 'fingerprint': http_fingerprint}
            
        except Exception as e:
            if self.config['graceful_degradation']:
                print(f"Fingerprinting error: {e}")
                return {'risk_score': 0}
            raise
    
    def _calculate_threat_score(self, ip_intelligence, behavioral_score, fingerprint_score):
        """Calculate combined threat score"""
        # Weight the different components
        weights = {
            'ip_reputation': 0.4,
            'behavioral': 0.3,
            'fingerprint': 0.3
        }
        
        ip_score = ip_intelligence.get('score', 0)
        
        total_score = (
            ip_score * weights['ip_reputation'] +
            behavioral_score * weights['behavioral'] +
            fingerprint_score * weights['fingerprint']
        )
        
        return min(total_score, 100)
    
    def _handle_high_threat(self, threat_score, client_info):
        """Handle high threat requests"""
        if self.config['strict_mode']:
            # Block the request
            return jsonify({
                'error': 'Access denied',
                'message': 'Your request has been blocked for security reasons.',
                'code': 'SECURITY_BLOCK'
            }), 403
        else:
            # In permissive mode, challenge instead of block
            return self._handle_medium_threat(threat_score, client_info)
    
    def _handle_medium_threat(self, threat_score, client_info):
        """Handle medium threat requests with challenges"""
        # Check if this IP has already been challenged recently
        session_key = f"challenge_completed_{client_info['ip_address']}"
        
        if session.get(session_key):
            # Already completed challenge, allow request
            return None
        
        # Generate browser challenge
        try:
            difficulty = 'high' if threat_score > 80 else 'medium'
            challenge = self.client_challenges.generate_browser_challenge(
                client_info['ip_address'],
                difficulty
            )
            
            # Store challenge in session
            session['pending_challenge'] = challenge['challenge_id']
            
            # Return challenge page
            return self._render_challenge_page(challenge)
            
        except Exception as e:
            if self.config['graceful_degradation']:
                print(f"Challenge generation error: {e}")
                return None  # Allow request on error
            raise
    
    def _handle_honeypot_trigger(self, honeypot_result, client_info):
        """Handle honeypot triggers"""
        # Add IP to blacklist
        self.ip_intelligence.add_to_blacklist(client_info['ip_address'])
        self.rate_limiter.add_to_blacklist(client_info['ip_address'])
        
        if honeypot_result['type'] == 'path_honeypot':
            # Return fake response for path honeypots
            fake_response = self.honeypots.get_decoy_response(
                client_info['path'],
                client_info['ip_address']
            )
            if fake_response:
                return jsonify(fake_response)
        
        # Default honeypot response
        return jsonify({
            'error': 'Not found',
            'message': 'The requested resource was not found.'
        }), 404
    
    def _create_rate_limit_response(self, rate_result):
        """Create rate limit response"""
        response = jsonify({
            'error': 'Rate limit exceeded',
            'message': f"Too many requests. Try again in {rate_result['retry_after']} seconds.",
            'retry_after': rate_result['retry_after']
        })
        response.status_code = 429
        
        # Add rate limit headers
        headers = self.rate_limiter.create_rate_limit_response(rate_result)
        for header, value in headers.items():
            response.headers[header] = value
        
        return response
    
    def _render_challenge_page(self, challenge):
        """Render browser challenge page"""
        # This would normally render an HTML template
        # For now, return a simple JSON response
        return jsonify({
            'challenge_required': True,
            'challenge_id': challenge['challenge_id'],
            'message': 'Browser verification required. Please complete the challenge.',
            'redirect_url': '/api/browser-challenge'
        }), 200
    
    def register_security_routes(self, app):
        """Register security-related routes"""
        
        @app.route('/api/browser-challenge', methods=['GET'])
        def browser_challenge():
            """Serve browser challenge"""
            challenge_id = session.get('pending_challenge')
            if not challenge_id:
                return jsonify({'error': 'No pending challenge'}), 400
            
            # Get challenge data
            challenge = self.client_challenges.active_challenges.get(challenge_id)
            if not challenge:
                return jsonify({'error': 'Challenge expired'}), 400
            
            # Return challenge page (would be HTML in production)
            return jsonify({
                'challenge_id': challenge_id,
                'instructions': 'Complete the browser verification challenges',
                'components': challenge.get('config', {})
            })
        
        @app.route('/api/verify-browser', methods=['POST'])
        def verify_browser():
            """Verify browser challenge response"""
            data = request.get_json()
            challenge_id = data.get('challenge_id')
            results = data.get('results', {})
            
            if not challenge_id:
                return jsonify({'error': 'Missing challenge ID'}), 400
            
            # Verify the challenge
            verification = self.client_challenges.verify_challenge_response(
                challenge_id, results
            )
            
            if verification['valid']:
                # Mark challenge as completed
                client_ip = self._get_client_ip()
                session[f"challenge_completed_{client_ip}"] = True
                session.pop('pending_challenge', None)
                
                return jsonify({
                    'verified': True,
                    'score': verification['score'],
                    'message': 'Verification successful'
                })
            else:
                return jsonify({
                    'verified': False,
                    'error': verification.get('error', 'Verification failed'),
                    'message': 'Please try again'
                }), 400
        
        @app.route('/api/security/stats', methods=['GET'])
        def security_stats():
            """Get security system statistics"""
            return jsonify({
                'system_stats': self.stats,
                'ip_intelligence': self.ip_intelligence.get_statistics(),
                'behavioral_analysis': self.behavioral_analysis.get_global_statistics(),
                'honeypots': self.honeypots.get_statistics(),
                'rate_limiting': self.rate_limiter.get_global_statistics(),
                'fingerprinting': self.fingerprinting.get_fingerprint_statistics()
            })
        
        @app.route('/api/honeypot-trigger', methods=['POST'])
        def honeypot_trigger():
            """Handle JavaScript honeypot triggers"""
            data = request.get_json()
            client_ip = self._get_client_ip()
            
            # Record the honeypot trigger
            self.honeypots._trigger_honeypot(
                client_ip,
                data.get('trap_type', 'js_trap'),
                data
            )
            
            return jsonify({'status': 'recorded'})
    
    def register_cleanup_tasks(self, app):
        """Register periodic cleanup tasks"""
        import threading
        
        def cleanup_task():
            while True:
                try:
                    # Cleanup old data from all components
                    self.ip_intelligence.ip_activity_log.clear()  # Simple cleanup
                    self.behavioral_analysis.cleanup_old_sessions()
                    self.client_challenges.cleanup_expired_challenges()
                    self.honeypots.cleanup_old_data()
                    
                    # Sleep for 5 minutes
                    time.sleep(300)
                    
                except Exception as e:
                    print(f"Cleanup task error: {e}")
                    time.sleep(60)  # Retry in 1 minute
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=cleanup_task)
        cleanup_thread.daemon = True
        cleanup_thread.start()
    
    def update_config(self, new_config):
        """Update security configuration"""
        self.config.update(new_config)
    
    def enable_strict_mode(self):
        """Enable strict security mode"""
        self.config['strict_mode'] = True
        self.config['challenge_threshold'] = 50
        self.config['block_threshold'] = 70
    
    def disable_strict_mode(self):
        """Disable strict security mode"""
        self.config['strict_mode'] = False
        self.config['challenge_threshold'] = 70
        self.config['block_threshold'] = 90
    
    def get_security_status(self):
        """Get current security system status"""
        return {
            'enabled': self.config['enabled'],
            'strict_mode': self.config['strict_mode'],
            'components': {
                'rate_limiting': self.config['rate_limiting_enabled'],
                'honeypots': self.config['honeypot_enabled'],
                'fingerprinting': self.config['fingerprinting_enabled'],
                'behavioral_analysis': self.config['behavioral_analysis_enabled']
            },
            'thresholds': {
                'challenge': self.config['challenge_threshold'],
                'block': self.config['block_threshold']
            },
            'statistics': self.stats
        }

