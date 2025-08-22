"""
Enhanced Fingerprinting and Device Identification System
Advanced in-house implementation for comprehensive client analysis
"""

import hashlib
import json
import time
import re
import base64
from collections import defaultdict
from datetime import datetime, timedelta

class AdvancedFingerprintEngine:
    def __init__(self):
        self.fingerprint_cache = {}
        self.device_profiles = defaultdict(dict)
        self.fingerprint_patterns = self._initialize_patterns()
        self.bot_signatures = self._initialize_bot_signatures()
        self.browser_profiles = self._initialize_browser_profiles()
        
    def _initialize_patterns(self):
        """Initialize fingerprinting patterns for analysis"""
        return {
            'bot_user_agents': [
                r'bot|crawler|spider|scraper',
                r'curl|wget|python|java|go|rust',
                r'headless|phantom|selenium|playwright',
                r'automation|test|monitor|check',
                r'scan|probe|fetch|http|client',
                r'library|framework|tool|script',
                r'api|service|worker|daemon'
            ],
            'browser_engines': {
                'webkit': r'webkit/(\d+)',
                'gecko': r'gecko/(\d+)',
                'trident': r'trident/(\d+)',
                'edge': r'edge/(\d+)',
                'blink': r'chrome/(\d+)'
            },
            'os_patterns': {
                'windows': r'windows nt (\d+\.\d+)',
                'macos': r'mac os x (\d+[._]\d+)',
                'linux': r'linux',
                'android': r'android (\d+)',
                'ios': r'os (\d+[._]\d+)',
                'chromeos': r'cros'
            },
            'device_patterns': {
                'mobile': r'mobile|phone|android|iphone',
                'tablet': r'tablet|ipad',
                'desktop': r'windows|macintosh|linux',
                'tv': r'smart-tv|tv|roku|chromecast',
                'console': r'playstation|xbox|nintendo'
            }
        }
    
    def _initialize_bot_signatures(self):
        """Initialize known bot fingerprint signatures"""
        return {
            'headless_chrome': {
                'user_agent_patterns': [r'headless', r'chrome.*headless'],
                'missing_features': ['webgl', 'audio_context', 'battery'],
                'suspicious_properties': {
                    'navigator.webdriver': True,
                    'window.chrome': None,
                    'navigator.permissions': None
                }
            },
            'selenium': {
                'user_agent_patterns': [r'selenium', r'webdriver'],
                'window_properties': ['_selenium', '__selenium_unwrapped', '__webdriver_script_fn'],
                'document_properties': ['$cdc_', '__$webdriverAsyncExecutor']
            },
            'phantomjs': {
                'user_agent_patterns': [r'phantom'],
                'window_properties': ['callPhantom', '_phantom', '__phantom'],
                'missing_features': ['touch_support', 'device_memory']
            },
            'puppeteer': {
                'user_agent_patterns': [r'chrome.*headless'],
                'chrome_properties': {
                    'runtime': None,
                    'loadTimes': None
                },
                'permissions_api': False
            },
            'playwright': {
                'user_agent_patterns': [r'playwright'],
                'window_properties': ['__playwright', '_playwright'],
                'webdriver_property': True
            }
        }
    
    def _initialize_browser_profiles(self):
        """Initialize legitimate browser profiles for comparison"""
        return {
            'chrome': {
                'expected_features': [
                    'webgl', 'audio_context', 'canvas', 'local_storage',
                    'session_storage', 'indexeddb', 'web_workers'
                ],
                'expected_properties': [
                    'navigator.userAgent', 'navigator.language', 'navigator.platform',
                    'navigator.cookieEnabled', 'navigator.onLine'
                ],
                'chrome_specific': ['chrome.runtime', 'chrome.loadTimes']
            },
            'firefox': {
                'expected_features': [
                    'webgl', 'audio_context', 'canvas', 'local_storage',
                    'session_storage', 'indexeddb', 'web_workers'
                ],
                'expected_properties': [
                    'navigator.userAgent', 'navigator.language', 'navigator.platform',
                    'navigator.cookieEnabled', 'navigator.buildID'
                ],
                'firefox_specific': ['navigator.mozApps', 'navigator.mozContacts']
            },
            'safari': {
                'expected_features': [
                    'webgl', 'audio_context', 'canvas', 'local_storage',
                    'session_storage', 'web_workers'
                ],
                'expected_properties': [
                    'navigator.userAgent', 'navigator.language', 'navigator.platform',
                    'navigator.cookieEnabled', 'navigator.vendor'
                ],
                'safari_specific': ['safari.pushNotification', 'webkit.messageHandlers']
            }
        }
    
    def analyze_http_fingerprint(self, headers, ip_address):
        """Analyze HTTP headers for fingerprinting"""
        fingerprint_data = {
            'timestamp': time.time(),
            'ip_address': ip_address,
            'headers': dict(headers),
            'analysis': {}
        }
        
        # Analyze User-Agent
        user_agent = headers.get('User-Agent', '')
        fingerprint_data['analysis']['user_agent'] = self._analyze_user_agent(user_agent)
        
        # Analyze Accept headers
        fingerprint_data['analysis']['accept_headers'] = self._analyze_accept_headers(headers)
        
        # Analyze header order and presence
        fingerprint_data['analysis']['header_analysis'] = self._analyze_header_patterns(headers)
        
        # Analyze HTTP/2 fingerprinting (if available)
        fingerprint_data['analysis']['http2_analysis'] = self._analyze_http2_patterns(headers)
        
        # Calculate header fingerprint hash
        fingerprint_data['header_hash'] = self._calculate_header_hash(headers)
        
        return fingerprint_data
    
    def analyze_javascript_fingerprint(self, js_data, ip_address):
        """Analyze JavaScript-collected fingerprint data"""
        fingerprint_data = {
            'timestamp': time.time(),
            'ip_address': ip_address,
            'js_data': js_data,
            'analysis': {}
        }
        
        # Analyze browser properties
        fingerprint_data['analysis']['browser_analysis'] = self._analyze_browser_properties(js_data)
        
        # Analyze canvas fingerprint
        if 'canvas_data' in js_data:
            fingerprint_data['analysis']['canvas_analysis'] = self._analyze_canvas_fingerprint(js_data['canvas_data'])
        
        # Analyze WebGL fingerprint
        if 'webgl_info' in js_data:
            fingerprint_data['analysis']['webgl_analysis'] = self._analyze_webgl_fingerprint(js_data['webgl_info'])
        
        # Analyze audio context fingerprint
        if 'audio_context' in js_data:
            fingerprint_data['analysis']['audio_analysis'] = self._analyze_audio_fingerprint(js_data['audio_context'])
        
        # Analyze screen and hardware info
        fingerprint_data['analysis']['hardware_analysis'] = self._analyze_hardware_info(js_data)
        
        # Analyze timing characteristics
        if 'timing_data' in js_data:
            fingerprint_data['analysis']['timing_analysis'] = self._analyze_timing_characteristics(js_data['timing_data'])
        
        # Detect automation tools
        fingerprint_data['analysis']['automation_detection'] = self._detect_automation_tools(js_data)
        
        # Calculate comprehensive fingerprint hash
        fingerprint_data['fingerprint_hash'] = self._calculate_js_fingerprint_hash(js_data)
        
        return fingerprint_data
    
    def _analyze_user_agent(self, user_agent):
        """Analyze User-Agent string for bot indicators"""
        analysis = {
            'raw': user_agent,
            'length': len(user_agent),
            'is_suspicious': False,
            'bot_indicators': [],
            'browser_info': {},
            'os_info': {},
            'device_info': {}
        }
        
        if not user_agent:
            analysis['is_suspicious'] = True
            analysis['bot_indicators'].append('missing_user_agent')
            return analysis
        
        user_agent_lower = user_agent.lower()
        
        # Check for bot patterns
        for pattern in self.fingerprint_patterns['bot_user_agents']:
            if re.search(pattern, user_agent_lower):
                analysis['is_suspicious'] = True
                analysis['bot_indicators'].append(f'pattern_match_{pattern}')
        
        # Analyze browser engine
        for engine, pattern in self.fingerprint_patterns['browser_engines'].items():
            match = re.search(pattern, user_agent_lower)
            if match:
                analysis['browser_info']['engine'] = engine
                analysis['browser_info']['version'] = match.group(1)
        
        # Analyze OS
        for os_name, pattern in self.fingerprint_patterns['os_patterns'].items():
            match = re.search(pattern, user_agent_lower)
            if match:
                analysis['os_info']['name'] = os_name
                if match.groups():
                    analysis['os_info']['version'] = match.group(1)
        
        # Analyze device type
        for device_type, pattern in self.fingerprint_patterns['device_patterns'].items():
            if re.search(pattern, user_agent_lower):
                analysis['device_info']['type'] = device_type
        
        # Check for suspicious characteristics
        if len(user_agent) < 20:
            analysis['is_suspicious'] = True
            analysis['bot_indicators'].append('too_short')
        elif len(user_agent) > 500:
            analysis['is_suspicious'] = True
            analysis['bot_indicators'].append('too_long')
        
        # Check for missing common browser components
        if 'mozilla' not in user_agent_lower and 'chrome' not in user_agent_lower:
            analysis['is_suspicious'] = True
            analysis['bot_indicators'].append('missing_browser_signature')
        
        return analysis
    
    def _analyze_accept_headers(self, headers):
        """Analyze Accept-* headers for bot indicators"""
        analysis = {
            'accept': headers.get('Accept', ''),
            'accept_language': headers.get('Accept-Language', ''),
            'accept_encoding': headers.get('Accept-Encoding', ''),
            'is_suspicious': False,
            'missing_headers': [],
            'suspicious_values': []
        }
        
        # Check for missing common headers
        expected_headers = ['Accept', 'Accept-Language', 'Accept-Encoding']
        for header in expected_headers:
            if header not in headers:
                analysis['missing_headers'].append(header)
                analysis['is_suspicious'] = True
        
        # Check for suspicious Accept header values
        accept_header = headers.get('Accept', '')
        if accept_header == '*/*':
            analysis['suspicious_values'].append('generic_accept')
            analysis['is_suspicious'] = True
        elif not accept_header:
            analysis['suspicious_values'].append('missing_accept')
            analysis['is_suspicious'] = True
        
        # Check Accept-Language
        accept_lang = headers.get('Accept-Language', '')
        if not accept_lang:
            analysis['suspicious_values'].append('missing_language')
            analysis['is_suspicious'] = True
        elif len(accept_lang.split(',')) == 1 and 'en' not in accept_lang:
            analysis['suspicious_values'].append('single_language')
        
        return analysis
    
    def _analyze_header_patterns(self, headers):
        """Analyze header order and patterns"""
        analysis = {
            'header_count': len(headers),
            'header_order': list(headers.keys()),
            'is_suspicious': False,
            'anomalies': []
        }
        
        # Check for too few headers (bots often send minimal headers)
        if len(headers) < 5:
            analysis['is_suspicious'] = True
            analysis['anomalies'].append('too_few_headers')
        
        # Check for unusual header order
        common_order = ['Host', 'User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding']
        header_keys = list(headers.keys())
        
        order_score = 0
        for i, expected_header in enumerate(common_order):
            if i < len(header_keys) and header_keys[i] == expected_header:
                order_score += 1
        
        if order_score < 3:  # Less than 3 headers in expected order
            analysis['is_suspicious'] = True
            analysis['anomalies'].append('unusual_header_order')
        
        # Check for bot-specific headers
        bot_headers = ['X-Forwarded-For', 'X-Real-IP', 'X-Automated', 'X-Bot']
        for header in bot_headers:
            if header in headers:
                analysis['is_suspicious'] = True
                analysis['anomalies'].append(f'bot_header_{header}')
        
        return analysis
    
    def _analyze_http2_patterns(self, headers):
        """Analyze HTTP/2 specific patterns"""
        analysis = {
            'http2_indicators': [],
            'is_http2': False,
            'suspicious_patterns': []
        }
        
        # Check for HTTP/2 pseudo-headers (these would be processed by the server)
        # In practice, these are handled by the web server and not visible in Flask
        # But we can check for other HTTP/2 indicators
        
        # Check for HTTP/2 specific header characteristics
        if ':authority' in headers or ':method' in headers:
            analysis['is_http2'] = True
            analysis['http2_indicators'].append('pseudo_headers_present')
        
        # Check for header case sensitivity (HTTP/2 requires lowercase)
        uppercase_headers = [h for h in headers.keys() if h != h.lower()]
        if uppercase_headers:
            analysis['suspicious_patterns'].append('uppercase_headers_in_http2')
        
        return analysis
    
    def _analyze_browser_properties(self, js_data):
        """Analyze browser properties for bot detection"""
        analysis = {
            'is_suspicious': False,
            'bot_indicators': [],
            'missing_properties': [],
            'suspicious_values': []
        }
        
        # Check for automation tool signatures
        for bot_type, signatures in self.bot_signatures.items():
            if self._check_bot_signature(js_data, signatures):
                analysis['is_suspicious'] = True
                analysis['bot_indicators'].append(bot_type)
        
        # Check for missing standard properties
        expected_properties = [
            'navigator.userAgent', 'navigator.language', 'navigator.platform',
            'screen.width', 'screen.height', 'navigator.cookieEnabled'
        ]
        
        for prop in expected_properties:
            if prop not in js_data or js_data[prop] is None:
                analysis['missing_properties'].append(prop)
        
        # Check for suspicious property values
        if 'navigator.webdriver' in js_data and js_data['navigator.webdriver']:
            analysis['is_suspicious'] = True
            analysis['bot_indicators'].append('webdriver_property')
        
        if 'navigator.languages' in js_data:
            languages = js_data['navigator.languages']
            if not languages or len(languages) == 0:
                analysis['suspicious_values'].append('empty_languages')
                analysis['is_suspicious'] = True
        
        # Check for headless browser indicators
        if 'navigator.plugins' in js_data:
            plugins = js_data['navigator.plugins']
            if not plugins or len(plugins) == 0:
                analysis['suspicious_values'].append('no_plugins')
                analysis['is_suspicious'] = True
        
        return analysis
    
    def _analyze_canvas_fingerprint(self, canvas_data):
        """Analyze canvas fingerprint for uniqueness and legitimacy"""
        analysis = {
            'is_valid': False,
            'is_suspicious': False,
            'characteristics': {}
        }
        
        if not canvas_data or not canvas_data.startswith('data:image/'):
            analysis['is_suspicious'] = True
            return analysis
        
        analysis['is_valid'] = True
        
        # Extract base64 data
        try:
            base64_data = canvas_data.split(',')[1]
            canvas_bytes = base64.b64decode(base64_data)
            
            analysis['characteristics'] = {
                'data_length': len(canvas_bytes),
                'hash': hashlib.sha256(canvas_bytes).hexdigest()[:16]
            }
            
            # Check for suspicious patterns
            if len(canvas_bytes) < 100:  # Very small canvas data
                analysis['is_suspicious'] = True
            
            # Check for identical canvas fingerprints (common in bots)
            # This would require storing previous fingerprints for comparison
            
        except Exception:
            analysis['is_suspicious'] = True
        
        return analysis
    
    def _analyze_webgl_fingerprint(self, webgl_info):
        """Analyze WebGL fingerprint"""
        analysis = {
            'is_available': bool(webgl_info),
            'is_suspicious': False,
            'characteristics': {}
        }
        
        if not webgl_info:
            analysis['is_suspicious'] = True
            return analysis
        
        # Analyze WebGL properties
        analysis['characteristics'] = {
            'vendor': webgl_info.get('vendor', ''),
            'renderer': webgl_info.get('renderer', ''),
            'version': webgl_info.get('version', '')
        }
        
        # Check for suspicious values
        vendor = webgl_info.get('vendor', '').lower()
        renderer = webgl_info.get('renderer', '').lower()
        
        if 'swiftshader' in renderer or 'llvmpipe' in renderer:
            analysis['is_suspicious'] = True  # Software rendering (common in headless)
        
        if not vendor or not renderer:
            analysis['is_suspicious'] = True
        
        return analysis
    
    def _analyze_audio_fingerprint(self, audio_info):
        """Analyze audio context fingerprint"""
        analysis = {
            'is_available': bool(audio_info),
            'is_suspicious': False,
            'characteristics': {}
        }
        
        if not audio_info:
            analysis['is_suspicious'] = True
            return analysis
        
        analysis['characteristics'] = {
            'sample_rate': audio_info.get('sample_rate'),
            'state': audio_info.get('state'),
            'max_channel_count': audio_info.get('max_channel_count')
        }
        
        # Check for suspicious values
        sample_rate = audio_info.get('sample_rate')
        if sample_rate and (sample_rate < 8000 or sample_rate > 192000):
            analysis['is_suspicious'] = True
        
        return analysis
    
    def _analyze_hardware_info(self, js_data):
        """Analyze hardware and system information"""
        analysis = {
            'screen_info': {},
            'hardware_info': {},
            'is_suspicious': False,
            'anomalies': []
        }
        
        # Analyze screen information
        screen_width = js_data.get('screen.width')
        screen_height = js_data.get('screen.height')
        
        if screen_width and screen_height:
            analysis['screen_info'] = {
                'width': screen_width,
                'height': screen_height,
                'ratio': round(screen_width / screen_height, 2)
            }
            
            # Check for suspicious screen dimensions
            if screen_width < 100 or screen_height < 100:
                analysis['is_suspicious'] = True
                analysis['anomalies'].append('tiny_screen')
            elif screen_width > 10000 or screen_height > 10000:
                analysis['is_suspicious'] = True
                analysis['anomalies'].append('huge_screen')
        
        # Analyze hardware concurrency
        hardware_concurrency = js_data.get('navigator.hardwareConcurrency')
        if hardware_concurrency:
            analysis['hardware_info']['cpu_cores'] = hardware_concurrency
            
            if hardware_concurrency > 64:  # Unusually high
                analysis['is_suspicious'] = True
                analysis['anomalies'].append('excessive_cpu_cores')
        
        # Analyze device memory
        device_memory = js_data.get('navigator.deviceMemory')
        if device_memory:
            analysis['hardware_info']['memory_gb'] = device_memory
        
        return analysis
    
    def _analyze_timing_characteristics(self, timing_data):
        """Analyze JavaScript execution timing characteristics"""
        analysis = {
            'is_suspicious': False,
            'characteristics': {},
            'anomalies': []
        }
        
        if 'execution_times' in timing_data:
            times = timing_data['execution_times']
            
            if times:
                import statistics
                analysis['characteristics'] = {
                    'count': len(times),
                    'average': statistics.mean(times),
                    'variance': statistics.variance(times) if len(times) > 1 else 0,
                    'min': min(times),
                    'max': max(times)
                }
                
                # Check for bot-like timing patterns
                variance = analysis['characteristics']['variance']
                if variance < 0.01:  # Very low variance
                    analysis['is_suspicious'] = True
                    analysis['anomalies'].append('low_timing_variance')
                
                avg_time = analysis['characteristics']['average']
                if avg_time < 0.001:  # Extremely fast execution
                    analysis['is_suspicious'] = True
                    analysis['anomalies'].append('extremely_fast_execution')
        
        return analysis
    
    def _detect_automation_tools(self, js_data):
        """Detect automation tools and frameworks"""
        detection = {
            'detected_tools': [],
            'confidence_score': 0,
            'indicators': []
        }
        
        # Check for Selenium
        selenium_indicators = [
            'window._selenium', 'window.__selenium_unwrapped',
            'document.$cdc_', 'navigator.webdriver'
        ]
        
        for indicator in selenium_indicators:
            if indicator in js_data and js_data[indicator]:
                detection['detected_tools'].append('selenium')
                detection['confidence_score'] += 25
                detection['indicators'].append(indicator)
        
        # Check for PhantomJS
        phantom_indicators = [
            'window.callPhantom', 'window._phantom', 'window.__phantom'
        ]
        
        for indicator in phantom_indicators:
            if indicator in js_data and js_data[indicator]:
                detection['detected_tools'].append('phantomjs')
                detection['confidence_score'] += 30
                detection['indicators'].append(indicator)
        
        # Check for headless Chrome
        if ('navigator.webdriver' in js_data and js_data['navigator.webdriver'] and
            'chrome' in js_data.get('navigator.userAgent', '').lower()):
            detection['detected_tools'].append('headless_chrome')
            detection['confidence_score'] += 20
            detection['indicators'].append('webdriver_chrome')
        
        # Check for Puppeteer
        if 'navigator.permissions' in js_data and not js_data['navigator.permissions']:
            detection['detected_tools'].append('puppeteer')
            detection['confidence_score'] += 15
            detection['indicators'].append('missing_permissions_api')
        
        return detection
    
    def _check_bot_signature(self, js_data, signatures):
        """Check if JavaScript data matches a bot signature"""
        matches = 0
        total_checks = 0
        
        # Check user agent patterns
        if 'user_agent_patterns' in signatures:
            user_agent = js_data.get('navigator.userAgent', '').lower()
            for pattern in signatures['user_agent_patterns']:
                total_checks += 1
                if re.search(pattern, user_agent):
                    matches += 1
        
        # Check for missing features
        if 'missing_features' in signatures:
            for feature in signatures['missing_features']:
                total_checks += 1
                if feature not in js_data or not js_data[feature]:
                    matches += 1
        
        # Check window properties
        if 'window_properties' in signatures:
            for prop in signatures['window_properties']:
                total_checks += 1
                if prop in js_data and js_data[prop]:
                    matches += 1
        
        # Check suspicious properties
        if 'suspicious_properties' in signatures:
            for prop, expected_value in signatures['suspicious_properties'].items():
                total_checks += 1
                if prop in js_data and js_data[prop] == expected_value:
                    matches += 1
        
        # Return True if more than 50% of checks match
        return total_checks > 0 and (matches / total_checks) > 0.5
    
    def _calculate_header_hash(self, headers):
        """Calculate a hash of HTTP headers for fingerprinting"""
        # Sort headers and create a consistent string
        sorted_headers = sorted(headers.items())
        header_string = '|'.join([f"{k}:{v}" for k, v in sorted_headers])
        return hashlib.sha256(header_string.encode()).hexdigest()
    
    def _calculate_js_fingerprint_hash(self, js_data):
        """Calculate a hash of JavaScript fingerprint data"""
        # Create a consistent string from JS data
        sorted_data = sorted(js_data.items())
        data_string = json.dumps(sorted_data, sort_keys=True)
        return hashlib.sha256(data_string.encode()).hexdigest()
    
    def create_comprehensive_fingerprint(self, http_fingerprint, js_fingerprint):
        """Create a comprehensive fingerprint combining HTTP and JS data"""
        comprehensive = {
            'timestamp': time.time(),
            'http_fingerprint': http_fingerprint,
            'js_fingerprint': js_fingerprint,
            'combined_analysis': {},
            'risk_score': 0,
            'fingerprint_id': None
        }
        
        # Combine risk assessments
        risk_factors = []
        risk_score = 0
        
        # HTTP-based risk factors
        if http_fingerprint['analysis']['user_agent']['is_suspicious']:
            risk_score += 30
            risk_factors.extend(http_fingerprint['analysis']['user_agent']['bot_indicators'])
        
        if http_fingerprint['analysis']['accept_headers']['is_suspicious']:
            risk_score += 20
            risk_factors.extend(http_fingerprint['analysis']['accept_headers']['missing_headers'])
        
        if http_fingerprint['analysis']['header_analysis']['is_suspicious']:
            risk_score += 15
            risk_factors.extend(http_fingerprint['analysis']['header_analysis']['anomalies'])
        
        # JS-based risk factors
        if js_fingerprint['analysis']['browser_analysis']['is_suspicious']:
            risk_score += 40
            risk_factors.extend(js_fingerprint['analysis']['browser_analysis']['bot_indicators'])
        
        if js_fingerprint['analysis']['automation_detection']['detected_tools']:
            risk_score += js_fingerprint['analysis']['automation_detection']['confidence_score']
            risk_factors.extend(js_fingerprint['analysis']['automation_detection']['detected_tools'])
        
        comprehensive['combined_analysis'] = {
            'risk_score': min(risk_score, 100),
            'risk_factors': risk_factors,
            'is_bot_likely': risk_score >= 50,
            'confidence_level': 'high' if risk_score >= 70 else 'medium' if risk_score >= 40 else 'low'
        }
        
        # Create unique fingerprint ID
        combined_hash = hashlib.sha256(
            (http_fingerprint['header_hash'] + js_fingerprint['fingerprint_hash']).encode()
        ).hexdigest()
        comprehensive['fingerprint_id'] = combined_hash[:16]
        
        # Cache the fingerprint
        self.fingerprint_cache[comprehensive['fingerprint_id']] = comprehensive
        
        return comprehensive
    
    def get_fingerprint_statistics(self):
        """Get fingerprinting system statistics"""
        current_time = time.time()
        
        # Count recent fingerprints (last hour)
        recent_fingerprints = sum(
            1 for fp in self.fingerprint_cache.values()
            if current_time - fp['timestamp'] < 3600
        )
        
        # Count high-risk fingerprints
        high_risk_count = sum(
            1 for fp in self.fingerprint_cache.values()
            if fp['combined_analysis']['risk_score'] >= 70
        )
        
        # Count detected automation tools
        automation_tools = defaultdict(int)
        for fp in self.fingerprint_cache.values():
            tools = fp['js_fingerprint']['analysis']['automation_detection']['detected_tools']
            for tool in tools:
                automation_tools[tool] += 1
        
        return {
            'total_fingerprints': len(self.fingerprint_cache),
            'recent_fingerprints': recent_fingerprints,
            'high_risk_fingerprints': high_risk_count,
            'automation_tools_detected': dict(automation_tools),
            'bot_signature_patterns': len(self.bot_signatures),
            'browser_profiles': len(self.browser_profiles)
        }

