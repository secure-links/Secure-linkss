"""
Advanced Behavioral Anomaly Detection System
In-house machine learning and pattern analysis for bot detection
"""

import time
import json
import hashlib
import math
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
import re

class BehavioralAnalysisEngine:
    def __init__(self):
        self.user_sessions = defaultdict(dict)
        self.behavioral_patterns = defaultdict(list)
        self.anomaly_thresholds = self._initialize_thresholds()
        self.feature_weights = self._initialize_feature_weights()
        self.session_timeout = 1800  # 30 minutes
        
        # Behavioral metrics storage
        self.timing_patterns = defaultdict(list)
        self.navigation_patterns = defaultdict(list)
        self.interaction_patterns = defaultdict(list)
        self.request_patterns = defaultdict(list)
        
        # Machine learning components (simplified)
        self.normal_behavior_model = {}
        self.anomaly_detection_model = {}
        
    def _initialize_thresholds(self):
        """Initialize anomaly detection thresholds"""
        return {
            'request_frequency': {
                'normal_max': 10,      # requests per minute
                'suspicious': 20,
                'bot_like': 50
            },
            'timing_regularity': {
                'normal_variance': 2.0,  # seconds variance
                'suspicious': 0.5,
                'bot_like': 0.1
            },
            'navigation_depth': {
                'normal_min': 2,       # pages visited
                'suspicious_max': 1,
                'bot_like_max': 0
            },
            'session_duration': {
                'normal_min': 30,      # seconds
                'suspicious_max': 10,
                'bot_like_max': 5
            },
            'interaction_diversity': {
                'normal_min': 3,       # different types of interactions
                'suspicious_max': 2,
                'bot_like_max': 1
            }
        }
    
    def _initialize_feature_weights(self):
        """Initialize feature importance weights for scoring"""
        return {
            'timing_regularity': 0.25,
            'request_frequency': 0.20,
            'navigation_patterns': 0.15,
            'interaction_diversity': 0.15,
            'session_characteristics': 0.10,
            'header_consistency': 0.10,
            'behavioral_entropy': 0.05
        }
    
    def analyze_request_behavior(self, session_id, request_data):
        """Analyze individual request behavior"""
        current_time = time.time()
        
        # Initialize session if new
        if session_id not in self.user_sessions:
            self.user_sessions[session_id] = {
                'start_time': current_time,
                'last_activity': current_time,
                'requests': [],
                'pages_visited': set(),
                'user_agents': set(),
                'referers': set(),
                'interactions': [],
                'timing_intervals': [],
                'behavioral_score': 0
            }
        
        session = self.user_sessions[session_id]
        
        # Update session data
        session['last_activity'] = current_time
        session['requests'].append({
            'timestamp': current_time,
            'path': request_data.get('path', ''),
            'method': request_data.get('method', 'GET'),
            'user_agent': request_data.get('user_agent', ''),
            'referer': request_data.get('referer', ''),
            'headers': request_data.get('headers', {}),
            'query_params': request_data.get('query_params', {}),
            'content_length': request_data.get('content_length', 0)
        })
        
        # Track unique values
        session['pages_visited'].add(request_data.get('path', ''))
        session['user_agents'].add(request_data.get('user_agent', ''))
        session['referers'].add(request_data.get('referer', ''))
        
        # Calculate timing intervals
        if len(session['requests']) > 1:
            last_request = session['requests'][-2]
            interval = current_time - last_request['timestamp']
            session['timing_intervals'].append(interval)
        
        # Analyze current behavior
        anomaly_score = self._calculate_anomaly_score(session_id)
        session['behavioral_score'] = anomaly_score
        
        return {
            'session_id': session_id,
            'anomaly_score': anomaly_score,
            'risk_level': self._classify_risk_level(anomaly_score),
            'behavioral_flags': self._get_behavioral_flags(session_id),
            'session_stats': self._get_session_stats(session_id)
        }
    
    def _calculate_anomaly_score(self, session_id):
        """Calculate comprehensive anomaly score for a session"""
        session = self.user_sessions[session_id]
        total_score = 0
        
        # 1. Timing Regularity Analysis
        timing_score = self._analyze_timing_patterns(session_id)
        total_score += timing_score * self.feature_weights['timing_regularity']
        
        # 2. Request Frequency Analysis
        frequency_score = self._analyze_request_frequency(session_id)
        total_score += frequency_score * self.feature_weights['request_frequency']
        
        # 3. Navigation Pattern Analysis
        navigation_score = self._analyze_navigation_patterns(session_id)
        total_score += navigation_score * self.feature_weights['navigation_patterns']
        
        # 4. Interaction Diversity Analysis
        interaction_score = self._analyze_interaction_diversity(session_id)
        total_score += interaction_score * self.feature_weights['interaction_diversity']
        
        # 5. Session Characteristics Analysis
        session_score = self._analyze_session_characteristics(session_id)
        total_score += session_score * self.feature_weights['session_characteristics']
        
        # 6. Header Consistency Analysis
        header_score = self._analyze_header_consistency(session_id)
        total_score += header_score * self.feature_weights['header_consistency']
        
        # 7. Behavioral Entropy Analysis
        entropy_score = self._analyze_behavioral_entropy(session_id)
        total_score += entropy_score * self.feature_weights['behavioral_entropy']
        
        return min(total_score, 100)
    
    def _analyze_timing_patterns(self, session_id):
        """Analyze timing patterns for bot-like regularity"""
        session = self.user_sessions[session_id]
        intervals = session['timing_intervals']
        
        if len(intervals) < 3:
            return 0
        
        # Calculate variance in timing
        try:
            variance = statistics.variance(intervals)
            mean_interval = statistics.mean(intervals)
            
            # Very regular timing is suspicious
            if variance < self.anomaly_thresholds['timing_regularity']['bot_like']:
                return 80
            elif variance < self.anomaly_thresholds['timing_regularity']['suspicious']:
                return 50
            
            # Very fast requests are suspicious
            if mean_interval < 0.5:  # Less than 500ms average
                return 70
            elif mean_interval < 1.0:  # Less than 1 second average
                return 40
            
            # Check for exact timing patterns (bot signatures)
            rounded_intervals = [round(interval, 1) for interval in intervals[-10:]]
            unique_intervals = len(set(rounded_intervals))
            if unique_intervals <= 2 and len(rounded_intervals) >= 5:
                return 90  # Very suspicious - only 1-2 unique intervals
            
        except statistics.StatisticsError:
            return 0
        
        return 0
    
    def _analyze_request_frequency(self, session_id):
        """Analyze request frequency patterns"""
        session = self.user_sessions[session_id]
        current_time = time.time()
        
        # Count requests in last minute
        recent_requests = [
            req for req in session['requests']
            if current_time - req['timestamp'] < 60
        ]
        
        requests_per_minute = len(recent_requests)
        
        if requests_per_minute >= self.anomaly_thresholds['request_frequency']['bot_like']:
            return 90
        elif requests_per_minute >= self.anomaly_thresholds['request_frequency']['suspicious']:
            return 60
        elif requests_per_minute > self.anomaly_thresholds['request_frequency']['normal_max']:
            return 30
        
        return 0
    
    def _analyze_navigation_patterns(self, session_id):
        """Analyze navigation patterns for human-like behavior"""
        session = self.user_sessions[session_id]
        
        # Check navigation depth
        pages_visited = len(session['pages_visited'])
        total_requests = len(session['requests'])
        
        if total_requests > 5:  # Only analyze if enough requests
            # Very low page diversity (hitting same endpoints repeatedly)
            if pages_visited <= self.anomaly_thresholds['navigation_depth']['bot_like_max']:
                return 85
            elif pages_visited <= self.anomaly_thresholds['navigation_depth']['suspicious_max']:
                return 60
            
            # Check for direct API access patterns
            api_requests = sum(1 for req in session['requests'] if '/api/' in req['path'])
            api_ratio = api_requests / total_requests
            
            if api_ratio > 0.8:  # More than 80% API requests
                return 70
            elif api_ratio > 0.5:  # More than 50% API requests
                return 40
        
        # Check for missing referers (direct access to deep pages)
        requests_without_referer = sum(
            1 for req in session['requests']
            if not req['referer'] and req['path'] not in ['/', '/index.html']
        )
        
        if requests_without_referer > total_requests * 0.7:
            return 50
        
        return 0
    
    def _analyze_interaction_diversity(self, session_id):
        """Analyze diversity of interactions"""
        session = self.user_sessions[session_id]
        
        # Count different types of requests
        methods = set(req['method'] for req in session['requests'])
        paths = session['pages_visited']
        user_agents = session['user_agents']
        
        interaction_types = len(methods) + min(len(paths), 5) + min(len(user_agents), 2)
        
        if interaction_types <= self.anomaly_thresholds['interaction_diversity']['bot_like_max']:
            return 80
        elif interaction_types <= self.anomaly_thresholds['interaction_diversity']['suspicious_max']:
            return 50
        elif interaction_types < self.anomaly_thresholds['interaction_diversity']['normal_min']:
            return 25
        
        return 0
    
    def _analyze_session_characteristics(self, session_id):
        """Analyze overall session characteristics"""
        session = self.user_sessions[session_id]
        current_time = time.time()
        
        session_duration = current_time - session['start_time']
        total_requests = len(session['requests'])
        
        # Very short sessions with many requests
        if session_duration <= self.anomaly_thresholds['session_duration']['bot_like_max']:
            if total_requests > 3:
                return 85
        elif session_duration <= self.anomaly_thresholds['session_duration']['suspicious_max']:
            if total_requests > 5:
                return 60
        
        # Check for burst patterns
        if total_requests > 10:
            first_half_time = session['requests'][total_requests//2]['timestamp'] - session['start_time']
            if first_half_time < 5:  # Half the requests in first 5 seconds
                return 70
        
        return 0
    
    def _analyze_header_consistency(self, session_id):
        """Analyze HTTP header consistency"""
        session = self.user_sessions[session_id]
        
        if len(session['requests']) < 2:
            return 0
        
        # Check user agent consistency
        user_agents = session['user_agents']
        if len(user_agents) > 1:
            return 60  # Changing user agents is suspicious
        
        # Check for missing common headers
        missing_headers_score = 0
        for req in session['requests'][-5:]:  # Check last 5 requests
            headers = req.get('headers', {})
            
            # Common headers that browsers typically send
            expected_headers = ['accept', 'accept-language', 'accept-encoding']
            missing_count = sum(1 for header in expected_headers if header not in headers)
            
            if missing_count >= 2:
                missing_headers_score += 20
        
        return min(missing_headers_score, 80)
    
    def _analyze_behavioral_entropy(self, session_id):
        """Analyze behavioral entropy (randomness vs predictability)"""
        session = self.user_sessions[session_id]
        
        if len(session['requests']) < 5:
            return 0
        
        # Calculate entropy of request paths
        path_counts = defaultdict(int)
        for req in session['requests']:
            path_counts[req['path']] += 1
        
        total_requests = len(session['requests'])
        entropy = 0
        
        for count in path_counts.values():
            probability = count / total_requests
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # Low entropy indicates repetitive behavior
        max_possible_entropy = math.log2(len(path_counts))
        if max_possible_entropy > 0:
            normalized_entropy = entropy / max_possible_entropy
            
            if normalized_entropy < 0.3:  # Very low entropy
                return 60
            elif normalized_entropy < 0.5:  # Low entropy
                return 30
        
        return 0
    
    def _classify_risk_level(self, anomaly_score):
        """Classify risk level based on anomaly score"""
        if anomaly_score >= 80:
            return 'high_risk'
        elif anomaly_score >= 60:
            return 'medium_risk'
        elif anomaly_score >= 40:
            return 'low_risk'
        else:
            return 'normal'
    
    def _get_behavioral_flags(self, session_id):
        """Get specific behavioral flags for a session"""
        session = self.user_sessions[session_id]
        flags = []
        
        # Timing flags
        if len(session['timing_intervals']) >= 3:
            try:
                variance = statistics.variance(session['timing_intervals'])
                if variance < 0.1:
                    flags.append('regular_timing')
                
                mean_interval = statistics.mean(session['timing_intervals'])
                if mean_interval < 0.5:
                    flags.append('rapid_requests')
            except statistics.StatisticsError:
                pass
        
        # Navigation flags
        if len(session['requests']) > 5:
            api_requests = sum(1 for req in session['requests'] if '/api/' in req['path'])
            if api_requests / len(session['requests']) > 0.8:
                flags.append('api_focused')
        
        # Session flags
        current_time = time.time()
        session_duration = current_time - session['start_time']
        if session_duration < 10 and len(session['requests']) > 5:
            flags.append('burst_activity')
        
        # Header flags
        if len(session['user_agents']) > 1:
            flags.append('changing_user_agent')
        
        return flags
    
    def _get_session_stats(self, session_id):
        """Get session statistics"""
        session = self.user_sessions[session_id]
        current_time = time.time()
        
        return {
            'duration': current_time - session['start_time'],
            'total_requests': len(session['requests']),
            'unique_pages': len(session['pages_visited']),
            'unique_user_agents': len(session['user_agents']),
            'avg_request_interval': (
                statistics.mean(session['timing_intervals'])
                if session['timing_intervals'] else 0
            )
        }
    
    def cleanup_old_sessions(self):
        """Clean up old sessions to prevent memory leaks"""
        current_time = time.time()
        expired_sessions = []
        
        for session_id, session in self.user_sessions.items():
            if current_time - session['last_activity'] > self.session_timeout:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.user_sessions[session_id]
        
        return len(expired_sessions)
    
    def get_global_statistics(self):
        """Get global behavioral analysis statistics"""
        current_time = time.time()
        
        active_sessions = 0
        total_requests = 0
        high_risk_sessions = 0
        
        for session in self.user_sessions.values():
            if current_time - session['last_activity'] < 300:  # Active in last 5 minutes
                active_sessions += 1
            
            total_requests += len(session['requests'])
            
            if session.get('behavioral_score', 0) >= 80:
                high_risk_sessions += 1
        
        return {
            'total_sessions': len(self.user_sessions),
            'active_sessions': active_sessions,
            'total_requests_analyzed': total_requests,
            'high_risk_sessions': high_risk_sessions,
            'risk_percentage': (
                (high_risk_sessions / len(self.user_sessions) * 100)
                if self.user_sessions else 0
            )
        }
    
    def update_behavior_model(self, session_data, is_bot=False):
        """Update the behavioral model with new training data"""
        # This is a simplified version - in production you'd use more sophisticated ML
        features = self._extract_features(session_data)
        
        if is_bot:
            # Update bot behavior patterns
            for feature, value in features.items():
                if feature not in self.anomaly_detection_model:
                    self.anomaly_detection_model[feature] = []
                self.anomaly_detection_model[feature].append(value)
        else:
            # Update normal behavior patterns
            for feature, value in features.items():
                if feature not in self.normal_behavior_model:
                    self.normal_behavior_model[feature] = []
                self.normal_behavior_model[feature].append(value)
    
    def _extract_features(self, session_data):
        """Extract behavioral features from session data"""
        features = {}
        
        if 'timing_intervals' in session_data and session_data['timing_intervals']:
            features['timing_variance'] = statistics.variance(session_data['timing_intervals'])
            features['timing_mean'] = statistics.mean(session_data['timing_intervals'])
        
        features['request_count'] = len(session_data.get('requests', []))
        features['page_diversity'] = len(session_data.get('pages_visited', set()))
        features['user_agent_changes'] = len(session_data.get('user_agents', set()))
        
        return features

