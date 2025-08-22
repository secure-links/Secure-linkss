"""
Advanced Client-Side Challenges and Proof-of-Work System
In-house implementation for browser verification without third-party services
"""

import hashlib
import hmac
import time
import json
import secrets
import base64
from datetime import datetime, timedelta

class ClientChallengeEngine:
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.active_challenges = {}
        self.challenge_timeout = 300  # 5 minutes
        self.pow_difficulty = 4  # Number of leading zeros required
        
    def generate_browser_challenge(self, ip_address, difficulty_level='medium'):
        """Generate comprehensive browser challenge"""
        challenge_id = secrets.token_hex(16)
        timestamp = int(time.time())
        
        # Adjust difficulty based on risk level
        difficulty_config = self._get_difficulty_config(difficulty_level)
        
        challenge_data = {
            'id': challenge_id,
            'timestamp': timestamp,
            'ip_address': ip_address,
            'difficulty': difficulty_level,
            'config': difficulty_config,
            'expires': timestamp + self.challenge_timeout
        }
        
        # Store challenge
        self.active_challenges[challenge_id] = challenge_data
        
        # Generate challenge components
        challenge_components = {
            'canvas_challenge': self._generate_canvas_challenge(),
            'timing_challenge': self._generate_timing_challenge(),
            'interaction_challenge': self._generate_interaction_challenge(),
            'proof_of_work': self._generate_proof_of_work(challenge_id, difficulty_config['pow_difficulty']),
            'fingerprint_challenge': self._generate_fingerprint_challenge(),
            'math_challenge': self._generate_math_challenge(difficulty_config['math_complexity']),
            'memory_challenge': self._generate_memory_challenge(difficulty_config['memory_size'])
        }
        
        # Create signed challenge
        challenge_payload = {
            'challenge_id': challenge_id,
            'timestamp': timestamp,
            'components': challenge_components,
            'timeout': self.challenge_timeout
        }
        
        signature = self._sign_challenge(challenge_payload)
        challenge_payload['signature'] = signature
        
        return challenge_payload
    
    def _get_difficulty_config(self, level):
        """Get configuration based on difficulty level"""
        configs = {
            'low': {
                'pow_difficulty': 3,
                'math_complexity': 1,
                'memory_size': 5,
                'timing_precision': 100,
                'canvas_complexity': 'simple'
            },
            'medium': {
                'pow_difficulty': 4,
                'math_complexity': 2,
                'memory_size': 8,
                'timing_precision': 50,
                'canvas_complexity': 'medium'
            },
            'high': {
                'pow_difficulty': 5,
                'math_complexity': 3,
                'memory_size': 12,
                'timing_precision': 25,
                'canvas_complexity': 'complex'
            },
            'extreme': {
                'pow_difficulty': 6,
                'math_complexity': 4,
                'memory_size': 16,
                'timing_precision': 10,
                'canvas_complexity': 'extreme'
            }
        }
        return configs.get(level, configs['medium'])
    
    def _generate_canvas_challenge(self):
        """Generate canvas fingerprinting challenge"""
        return {
            'type': 'canvas_fingerprint',
            'instructions': [
                'Create canvas with specific dimensions',
                'Draw text with specific font and color',
                'Draw geometric shapes',
                'Apply transformations',
                'Extract image data'
            ],
            'parameters': {
                'width': 300,
                'height': 150,
                'text': f"Challenge-{secrets.token_hex(4)}",
                'font': '14px Arial',
                'color': '#2d3748',
                'shapes': ['rectangle', 'circle', 'line'],
                'transformations': ['rotate', 'scale']
            }
        }
    
    def _generate_timing_challenge(self):
        """Generate timing-based challenge"""
        return {
            'type': 'timing_analysis',
            'instructions': [
                'Measure JavaScript execution timing',
                'Perform multiple iterations',
                'Calculate timing statistics'
            ],
            'parameters': {
                'iterations': 100,
                'operations': ['math', 'string', 'array'],
                'precision_required': 'microsecond'
            }
        }
    
    def _generate_interaction_challenge(self):
        """Generate user interaction challenge"""
        return {
            'type': 'interaction_verification',
            'instructions': [
                'Detect mouse movements',
                'Track keyboard events',
                'Measure interaction patterns'
            ],
            'parameters': {
                'min_mouse_events': 5,
                'min_movement_distance': 100,
                'interaction_timeout': 30000  # 30 seconds
            }
        }
    
    def _generate_proof_of_work(self, challenge_id, difficulty):
        """Generate proof-of-work challenge"""
        nonce_prefix = secrets.token_hex(8)
        target = '0' * difficulty
        
        return {
            'type': 'proof_of_work',
            'instructions': [
                'Find nonce that produces hash with required leading zeros',
                'Use SHA-256 hashing algorithm',
                'Increment nonce until target is met'
            ],
            'parameters': {
                'challenge_id': challenge_id,
                'nonce_prefix': nonce_prefix,
                'target': target,
                'difficulty': difficulty,
                'algorithm': 'sha256'
            }
        }
    
    def _generate_fingerprint_challenge(self):
        """Generate comprehensive fingerprinting challenge"""
        return {
            'type': 'browser_fingerprint',
            'instructions': [
                'Collect browser characteristics',
                'Analyze system properties',
                'Generate unique fingerprint'
            ],
            'parameters': {
                'required_properties': [
                    'screen_resolution',
                    'timezone',
                    'language',
                    'platform',
                    'user_agent',
                    'plugins',
                    'fonts',
                    'webgl_info',
                    'audio_context'
                ]
            }
        }
    
    def _generate_math_challenge(self, complexity):
        """Generate mathematical challenge"""
        challenges = {
            1: {
                'operations': ['addition', 'subtraction'],
                'range': (1, 100),
                'count': 3
            },
            2: {
                'operations': ['multiplication', 'division'],
                'range': (1, 50),
                'count': 5
            },
            3: {
                'operations': ['modulo', 'power'],
                'range': (1, 20),
                'count': 7
            },
            4: {
                'operations': ['fibonacci', 'prime'],
                'range': (1, 15),
                'count': 10
            }
        }
        
        config = challenges.get(complexity, challenges[2])
        
        return {
            'type': 'mathematical_proof',
            'instructions': [
                'Solve mathematical problems',
                'Perform calculations in JavaScript',
                'Return results in specified format'
            ],
            'parameters': config
        }
    
    def _generate_memory_challenge(self, size):
        """Generate memory allocation challenge"""
        return {
            'type': 'memory_allocation',
            'instructions': [
                'Allocate specified amount of memory',
                'Perform operations on allocated data',
                'Measure memory usage patterns'
            ],
            'parameters': {
                'allocation_size': size * 1024 * 1024,  # MB
                'operations': ['fill', 'sort', 'search'],
                'iterations': 3
            }
        }
    
    def _sign_challenge(self, challenge_data):
        """Sign challenge data with HMAC"""
        challenge_string = json.dumps(challenge_data, sort_keys=True)
        signature = hmac.new(
            self.secret_key.encode(),
            challenge_string.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def verify_challenge_response(self, challenge_id, response_data):
        """Verify challenge response from client"""
        if challenge_id not in self.active_challenges:
            return {
                'valid': False,
                'error': 'Challenge not found or expired',
                'score': 0
            }
        
        challenge = self.active_challenges[challenge_id]
        current_time = int(time.time())
        
        # Check if challenge has expired
        if current_time > challenge['expires']:
            del self.active_challenges[challenge_id]
            return {
                'valid': False,
                'error': 'Challenge expired',
                'score': 0
            }
        
        # Verify each component
        verification_results = {}
        total_score = 0
        max_score = 0
        
        # Verify canvas challenge
        if 'canvas_result' in response_data:
            canvas_score = self._verify_canvas_response(
                challenge['config'],
                response_data['canvas_result']
            )
            verification_results['canvas'] = canvas_score
            total_score += canvas_score['score']
            max_score += 20
        
        # Verify timing challenge
        if 'timing_result' in response_data:
            timing_score = self._verify_timing_response(
                challenge['config'],
                response_data['timing_result']
            )
            verification_results['timing'] = timing_score
            total_score += timing_score['score']
            max_score += 15
        
        # Verify proof of work
        if 'pow_result' in response_data:
            pow_score = self._verify_pow_response(
                challenge_id,
                challenge['config'],
                response_data['pow_result']
            )
            verification_results['proof_of_work'] = pow_score
            total_score += pow_score['score']
            max_score += 25
        
        # Verify fingerprint
        if 'fingerprint_result' in response_data:
            fingerprint_score = self._verify_fingerprint_response(
                challenge['config'],
                response_data['fingerprint_result']
            )
            verification_results['fingerprint'] = fingerprint_score
            total_score += fingerprint_score['score']
            max_score += 20
        
        # Verify math challenge
        if 'math_result' in response_data:
            math_score = self._verify_math_response(
                challenge['config'],
                response_data['math_result']
            )
            verification_results['math'] = math_score
            total_score += math_score['score']
            max_score += 10
        
        # Verify interaction challenge
        if 'interaction_result' in response_data:
            interaction_score = self._verify_interaction_response(
                challenge['config'],
                response_data['interaction_result']
            )
            verification_results['interaction'] = interaction_score
            total_score += interaction_score['score']
            max_score += 10
        
        # Calculate final score
        final_score = (total_score / max_score * 100) if max_score > 0 else 0
        
        # Clean up challenge
        del self.active_challenges[challenge_id]
        
        return {
            'valid': final_score >= 70,  # Require 70% to pass
            'score': final_score,
            'component_results': verification_results,
            'challenge_level': challenge['difficulty']
        }
    
    def _verify_canvas_response(self, config, canvas_result):
        """Verify canvas fingerprinting response"""
        score = 0
        
        # Check if canvas data is present and valid
        if 'canvas_data' in canvas_result and canvas_result['canvas_data']:
            score += 10
            
            # Check canvas data format
            if canvas_result['canvas_data'].startswith('data:image/png;base64,'):
                score += 5
            
            # Check canvas dimensions
            if ('width' in canvas_result and 
                canvas_result['width'] == config.get('canvas_complexity', {}).get('width', 300)):
                score += 3
            
            if ('height' in canvas_result and 
                canvas_result['height'] == config.get('canvas_complexity', {}).get('height', 150)):
                score += 2
        
        return {
            'score': score,
            'max_score': 20,
            'details': 'Canvas fingerprint verification'
        }
    
    def _verify_timing_response(self, config, timing_result):
        """Verify timing challenge response"""
        score = 0
        
        if 'execution_times' in timing_result:
            times = timing_result['execution_times']
            
            # Check if timing data is reasonable
            if isinstance(times, list) and len(times) >= 10:
                score += 5
                
                # Check timing variance (humans have more variance than bots)
                if len(times) > 1:
                    import statistics
                    try:
                        variance = statistics.variance(times)
                        if variance > 0.1:  # Some variance is expected
                            score += 5
                        if variance < 10:   # But not too much
                            score += 5
                    except:
                        pass
        
        return {
            'score': score,
            'max_score': 15,
            'details': 'Timing analysis verification'
        }
    
    def _verify_pow_response(self, challenge_id, config, pow_result):
        """Verify proof of work response"""
        score = 0
        
        if 'nonce' in pow_result and 'hash' in pow_result:
            # Verify the proof of work
            nonce = pow_result['nonce']
            provided_hash = pow_result['hash']
            
            # Reconstruct the hash
            data = f"{challenge_id}{nonce}"
            calculated_hash = hashlib.sha256(data.encode()).hexdigest()
            
            if calculated_hash == provided_hash:
                score += 10
                
                # Check if hash meets difficulty requirement
                difficulty = config.get('pow_difficulty', 4)
                if calculated_hash.startswith('0' * difficulty):
                    score += 15
        
        return {
            'score': score,
            'max_score': 25,
            'details': 'Proof of work verification'
        }
    
    def _verify_fingerprint_response(self, config, fingerprint_result):
        """Verify browser fingerprint response"""
        score = 0
        required_props = [
            'screen_resolution', 'timezone', 'language', 'platform',
            'user_agent', 'plugins', 'webgl_info'
        ]
        
        for prop in required_props:
            if prop in fingerprint_result and fingerprint_result[prop]:
                score += 2
        
        # Bonus for additional properties
        if len(fingerprint_result) > len(required_props):
            score += 6
        
        return {
            'score': min(score, 20),
            'max_score': 20,
            'details': 'Browser fingerprint verification'
        }
    
    def _verify_math_response(self, config, math_result):
        """Verify mathematical challenge response"""
        score = 0
        
        if 'answers' in math_result:
            answers = math_result['answers']
            
            # Simple verification (in production, you'd store expected answers)
            if isinstance(answers, list) and len(answers) >= 3:
                score += 5
                
                # Check if answers are reasonable numbers
                valid_answers = sum(1 for ans in answers if isinstance(ans, (int, float)))
                score += min(valid_answers, 5)
        
        return {
            'score': score,
            'max_score': 10,
            'details': 'Mathematical challenge verification'
        }
    
    def _verify_interaction_response(self, config, interaction_result):
        """Verify user interaction response"""
        score = 0
        
        if 'mouse_events' in interaction_result:
            mouse_events = interaction_result['mouse_events']
            if len(mouse_events) >= 3:
                score += 5
        
        if 'total_distance' in interaction_result:
            distance = interaction_result['total_distance']
            if distance >= 50:  # Minimum mouse movement
                score += 5
        
        return {
            'score': score,
            'max_score': 10,
            'details': 'User interaction verification'
        }
    
    def cleanup_expired_challenges(self):
        """Clean up expired challenges"""
        current_time = int(time.time())
        expired_challenges = [
            challenge_id for challenge_id, challenge in self.active_challenges.items()
            if current_time > challenge['expires']
        ]
        
        for challenge_id in expired_challenges:
            del self.active_challenges[challenge_id]
        
        return len(expired_challenges)
    
    def get_challenge_statistics(self):
        """Get challenge system statistics"""
        current_time = int(time.time())
        
        active_challenges = len(self.active_challenges)
        expired_count = sum(
            1 for challenge in self.active_challenges.values()
            if current_time > challenge['expires']
        )
        
        difficulty_distribution = {}
        for challenge in self.active_challenges.values():
            difficulty = challenge['difficulty']
            difficulty_distribution[difficulty] = difficulty_distribution.get(difficulty, 0) + 1
        
        return {
            'active_challenges': active_challenges,
            'expired_challenges': expired_count,
            'difficulty_distribution': difficulty_distribution,
            'challenge_timeout': self.challenge_timeout
        }

