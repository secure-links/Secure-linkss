"""
Advanced Honeypots and Trap Mechanisms
In-house implementation for detecting and trapping automated traffic
"""

import time
import json
import secrets
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from flask import request, session

class HoneypotEngine:
    def __init__(self):
        self.trapped_ips = set()
        self.honeypot_interactions = defaultdict(list)
        self.trap_triggers = defaultdict(int)
        self.decoy_sessions = {}
        
        # Honeypot configurations
        self.honeypot_paths = self._initialize_honeypot_paths()
        self.hidden_fields = self._initialize_hidden_fields()
        self.decoy_endpoints = self._initialize_decoy_endpoints()
        self.trap_cookies = self._initialize_trap_cookies()
        
    def _initialize_honeypot_paths(self):
        """Initialize honeypot paths that should never be accessed by legitimate users"""
        return {
            # Admin honeypots
            '/admin.php': 'php_admin_trap',
            '/administrator/': 'admin_trap',
            '/wp-admin/': 'wordpress_trap',
            '/phpmyadmin/': 'phpmyadmin_trap',
            '/cpanel/': 'cpanel_trap',
            '/webmin/': 'webmin_trap',
            '/plesk/': 'plesk_trap',
            
            # Common vulnerability paths
            '/.env': 'env_file_trap',
            '/config.php': 'config_trap',
            '/database.php': 'database_trap',
            '/backup.sql': 'backup_trap',
            '/dump.sql': 'sql_dump_trap',
            '/config.json': 'config_json_trap',
            '/settings.ini': 'settings_trap',
            
            # Hidden directories
            '/.git/config': 'git_config_trap',
            '/.svn/entries': 'svn_trap',
            '/.htaccess': 'htaccess_trap',
            '/web.config': 'webconfig_trap',
            
            # Fake API endpoints
            '/api/admin/users': 'admin_api_trap',
            '/api/internal/config': 'internal_api_trap',
            '/api/debug/info': 'debug_api_trap',
            '/api/backup/download': 'backup_api_trap',
            
            # Common bot targets
            '/sitemap_index.xml': 'sitemap_trap',
            '/feed.xml': 'feed_trap',
            '/rss.xml': 'rss_trap',
            '/atom.xml': 'atom_trap',
            
            # Security scanner traps
            '/security.txt': 'security_txt_trap',
            '/.well-known/security.txt': 'wellknown_security_trap',
            '/crossdomain.xml': 'crossdomain_trap',
            '/clientaccesspolicy.xml': 'clientaccess_trap',
            
            # Fake login pages
            '/login.php': 'fake_login_trap',
            '/signin.html': 'fake_signin_trap',
            '/auth/login': 'fake_auth_trap',
            
            # Development/testing paths
            '/test.php': 'test_file_trap',
            '/debug.php': 'debug_file_trap',
            '/info.php': 'info_file_trap',
            '/phpinfo.php': 'phpinfo_trap',
            
            # Backup file traps
            '/backup.zip': 'backup_zip_trap',
            '/site.tar.gz': 'site_backup_trap',
            '/database.bak': 'database_backup_trap',
            
            # Common CMS paths
            '/drupal/': 'drupal_trap',
            '/joomla/': 'joomla_trap',
            '/magento/': 'magento_trap',
            '/prestashop/': 'prestashop_trap'
        }
    
    def _initialize_hidden_fields(self):
        """Initialize hidden form fields that should never be filled by humans"""
        return {
            'email_confirm': 'hidden_email_trap',
            'website_url': 'hidden_url_trap',
            'company_name': 'hidden_company_trap',
            'phone_number': 'hidden_phone_trap',
            'address_line': 'hidden_address_trap',
            'zip_code': 'hidden_zip_trap',
            'credit_card': 'hidden_cc_trap',
            'ssn': 'hidden_ssn_trap',
            'password_confirm': 'hidden_password_trap',
            'username_alt': 'hidden_username_trap'
        }
    
    def _initialize_decoy_endpoints(self):
        """Initialize decoy API endpoints with fake data"""
        return {
            '/api/users/list': {
                'method': 'GET',
                'trap_type': 'user_enumeration',
                'fake_response': {
                    'users': [
                        {'id': 1, 'username': 'admin', 'email': 'admin@example.com'},
                        {'id': 2, 'username': 'user', 'email': 'user@example.com'},
                        {'id': 3, 'username': 'test', 'email': 'test@example.com'}
                    ]
                }
            },
            '/api/config/database': {
                'method': 'GET',
                'trap_type': 'config_access',
                'fake_response': {
                    'host': 'localhost',
                    'database': 'production_db',
                    'username': 'db_user',
                    'password': 'fake_password_123'
                }
            },
            '/api/admin/settings': {
                'method': 'GET',
                'trap_type': 'admin_access',
                'fake_response': {
                    'debug_mode': True,
                    'api_keys': ['fake_key_123', 'fake_key_456'],
                    'secret_token': 'fake_secret_token'
                }
            },
            '/api/backup/files': {
                'method': 'GET',
                'trap_type': 'backup_access',
                'fake_response': {
                    'files': [
                        'backup_2024_01_01.sql',
                        'site_backup_2024_01_01.tar.gz',
                        'user_data_export.csv'
                    ]
                }
            }
        }
    
    def _initialize_trap_cookies(self):
        """Initialize trap cookies that should never be sent by legitimate browsers"""
        return {
            'bot_detector': 'bot_cookie_trap',
            'crawler_id': 'crawler_cookie_trap',
            'automation_flag': 'automation_cookie_trap',
            'headless_browser': 'headless_cookie_trap',
            'selenium_driver': 'selenium_cookie_trap'
        }
    
    def check_honeypot_access(self, path, ip_address, user_agent, headers):
        """Check if the accessed path is a honeypot"""
        if path in self.honeypot_paths:
            trap_type = self.honeypot_paths[path]
            self._trigger_honeypot(ip_address, trap_type, {
                'path': path,
                'user_agent': user_agent,
                'headers': dict(headers),
                'timestamp': time.time()
            })
            return True
        return False
    
    def check_hidden_field_submission(self, form_data, ip_address):
        """Check if any hidden honeypot fields were submitted"""
        triggered_traps = []
        
        for field_name, trap_type in self.hidden_fields.items():
            if field_name in form_data and form_data[field_name]:
                # Hidden field was filled - this is a bot
                self._trigger_honeypot(ip_address, trap_type, {
                    'field': field_name,
                    'value': form_data[field_name],
                    'form_data': dict(form_data),
                    'timestamp': time.time()
                })
                triggered_traps.append(trap_type)
        
        return triggered_traps
    
    def check_decoy_endpoint_access(self, path, method, ip_address, user_agent):
        """Check if a decoy API endpoint was accessed"""
        if path in self.decoy_endpoints:
            endpoint_config = self.decoy_endpoints[path]
            if method.upper() == endpoint_config['method'].upper():
                self._trigger_honeypot(ip_address, endpoint_config['trap_type'], {
                    'endpoint': path,
                    'method': method,
                    'user_agent': user_agent,
                    'timestamp': time.time()
                })
                return endpoint_config['fake_response']
        return None
    
    def check_trap_cookies(self, cookies, ip_address):
        """Check for trap cookies that indicate bot activity"""
        triggered_traps = []
        
        for cookie_name, trap_type in self.trap_cookies.items():
            if cookie_name in cookies:
                self._trigger_honeypot(ip_address, trap_type, {
                    'cookie': cookie_name,
                    'value': cookies[cookie_name],
                    'all_cookies': dict(cookies),
                    'timestamp': time.time()
                })
                triggered_traps.append(trap_type)
        
        return triggered_traps
    
    def generate_honeypot_html(self):
        """Generate HTML with hidden honeypot elements"""
        honeypot_html = []
        
        # Hidden form fields
        for field_name in list(self.hidden_fields.keys())[:3]:  # Use only a few
            honeypot_html.append(f'''
                <input type="text" name="{field_name}" style="display:none !important; visibility:hidden !important; position:absolute !important; left:-9999px !important;" tabindex="-1" autocomplete="off">
            ''')
        
        # Hidden links
        hidden_paths = list(self.honeypot_paths.keys())[:5]  # Use only a few
        for path in hidden_paths:
            honeypot_html.append(f'''
                <a href="{path}" style="display:none !important; visibility:hidden !important; position:absolute !important; left:-9999px !important;">Hidden Link</a>
            ''')
        
        # CSS-based traps
        honeypot_html.append('''
            <style>
                .honeypot-trap {
                    display: none !important;
                    visibility: hidden !important;
                    position: absolute !important;
                    left: -9999px !important;
                    top: -9999px !important;
                    width: 0 !important;
                    height: 0 !important;
                    opacity: 0 !important;
                }
            </style>
            <div class="honeypot-trap">
                <input type="text" name="bot_field" value="">
                <a href="/admin.php">Admin</a>
                <a href="/.env">Config</a>
            </div>
        ''')
        
        return '\n'.join(honeypot_html)
    
    def generate_javascript_traps(self):
        """Generate JavaScript-based traps"""
        js_traps = '''
        <script>
        (function() {
            // Trap for automated form filling
            var trapFields = ''' + json.dumps(list(self.hidden_fields.keys())[:3]) + ''';
            trapFields.forEach(function(fieldName) {
                var field = document.querySelector('input[name="' + fieldName + '"]');
                if (field) {
                    Object.defineProperty(field, 'value', {
                        set: function(val) {
                            if (val && val.length > 0) {
                                // Bot detected - field should never be filled
                                fetch('/api/honeypot-trigger', {
                                    method: 'POST',
                                    headers: {'Content-Type': 'application/json'},
                                    body: JSON.stringify({
                                        trap_type: 'js_field_trap',
                                        field: fieldName,
                                        value: val,
                                        timestamp: Date.now()
                                    })
                                });
                            }
                        },
                        get: function() {
                            return this._value || '';
                        }
                    });
                }
            });
            
            // Trap for headless browser detection
            if (navigator.webdriver || window.phantom || window._phantom || window.callPhantom) {
                fetch('/api/honeypot-trigger', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        trap_type: 'headless_browser_trap',
                        details: {
                            webdriver: !!navigator.webdriver,
                            phantom: !!(window.phantom || window._phantom),
                            callPhantom: !!window.callPhantom
                        },
                        timestamp: Date.now()
                    })
                });
            }
            
            // Trap for automated clicking
            var trapLinks = document.querySelectorAll('a[href*="admin"], a[href*=".env"], a[href*="config"]');
            trapLinks.forEach(function(link) {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    fetch('/api/honeypot-trigger', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            trap_type: 'automated_click_trap',
                            href: this.href,
                            timestamp: Date.now()
                        })
                    });
                });
            });
            
            // Trap for rapid navigation
            var navigationCount = 0;
            var navigationStart = Date.now();
            
            window.addEventListener('beforeunload', function() {
                navigationCount++;
                var timeDiff = Date.now() - navigationStart;
                
                if (navigationCount > 5 && timeDiff < 5000) {
                    // More than 5 navigations in 5 seconds
                    navigator.sendBeacon('/api/honeypot-trigger', JSON.stringify({
                        trap_type: 'rapid_navigation_trap',
                        navigation_count: navigationCount,
                        time_diff: timeDiff,
                        timestamp: Date.now()
                    }));
                }
            });
        })();
        </script>
        '''
        return js_traps
    
    def _trigger_honeypot(self, ip_address, trap_type, details):
        """Trigger a honeypot and record the interaction"""
        self.trapped_ips.add(ip_address)
        self.trap_triggers[ip_address] += 1
        
        interaction = {
            'ip_address': ip_address,
            'trap_type': trap_type,
            'details': details,
            'timestamp': time.time()
        }
        
        self.honeypot_interactions[ip_address].append(interaction)
        
        # Log the honeypot trigger
        print(f"HONEYPOT TRIGGERED: {trap_type} by {ip_address}")
        
        return interaction
    
    def is_ip_trapped(self, ip_address):
        """Check if an IP address has triggered honeypots"""
        return ip_address in self.trapped_ips
    
    def get_trap_count(self, ip_address):
        """Get the number of traps triggered by an IP"""
        return self.trap_triggers.get(ip_address, 0)
    
    def get_ip_interactions(self, ip_address):
        """Get all honeypot interactions for an IP"""
        return self.honeypot_interactions.get(ip_address, [])
    
    def create_decoy_session(self, ip_address):
        """Create a decoy session with fake data for trapped IPs"""
        session_id = secrets.token_hex(16)
        
        decoy_data = {
            'session_id': session_id,
            'ip_address': ip_address,
            'created': time.time(),
            'fake_user_id': secrets.randbelow(1000) + 1000,
            'fake_username': f"user_{secrets.randbelow(9999)}",
            'fake_email': f"user{secrets.randbelow(9999)}@example.com",
            'fake_permissions': ['read', 'write'],
            'fake_api_key': secrets.token_hex(32),
            'fake_session_token': secrets.token_hex(64)
        }
        
        self.decoy_sessions[session_id] = decoy_data
        return decoy_data
    
    def get_decoy_response(self, path, ip_address):
        """Get a decoy response for trapped IPs"""
        if not self.is_ip_trapped(ip_address):
            return None
        
        # Create or get decoy session
        decoy_session = None
        for session_data in self.decoy_sessions.values():
            if session_data['ip_address'] == ip_address:
                decoy_session = session_data
                break
        
        if not decoy_session:
            decoy_session = self.create_decoy_session(ip_address)
        
        # Return fake data based on the path
        if '/api/user' in path:
            return {
                'user_id': decoy_session['fake_user_id'],
                'username': decoy_session['fake_username'],
                'email': decoy_session['fake_email'],
                'permissions': decoy_session['fake_permissions'],
                'api_key': decoy_session['fake_api_key']
            }
        elif '/api/session' in path:
            return {
                'session_id': decoy_session['session_id'],
                'token': decoy_session['fake_session_token'],
                'expires': int(time.time()) + 3600
            }
        elif '/api/config' in path:
            return {
                'database_host': 'fake-db.example.com',
                'database_name': 'fake_production',
                'api_endpoint': 'https://fake-api.example.com',
                'secret_key': 'fake_secret_key_123456'
            }
        else:
            return {
                'status': 'success',
                'message': 'Fake response for trapped IP',
                'data': {'fake': True}
            }
    
    def analyze_bot_behavior(self, ip_address):
        """Analyze bot behavior based on honeypot interactions"""
        interactions = self.get_ip_interactions(ip_address)
        
        if not interactions:
            return {
                'is_bot': False,
                'confidence': 0,
                'behavior_patterns': []
            }
        
        behavior_patterns = []
        confidence_score = 0
        
        # Analyze trap types
        trap_types = [interaction['trap_type'] for interaction in interactions]
        unique_traps = set(trap_types)
        
        # Multiple different traps = higher confidence
        if len(unique_traps) >= 3:
            confidence_score += 40
            behavior_patterns.append('multiple_trap_types')
        elif len(unique_traps) >= 2:
            confidence_score += 25
            behavior_patterns.append('diverse_trapping')
        
        # Rapid triggering
        if len(interactions) >= 5:
            confidence_score += 30
            behavior_patterns.append('rapid_triggering')
        
        # Specific high-confidence traps
        high_confidence_traps = [
            'hidden_field_trap', 'headless_browser_trap', 'automated_click_trap'
        ]
        
        for trap_type in high_confidence_traps:
            if trap_type in trap_types:
                confidence_score += 20
                behavior_patterns.append(f'triggered_{trap_type}')
        
        # Time-based analysis
        if len(interactions) >= 2:
            time_diffs = []
            for i in range(1, len(interactions)):
                time_diff = interactions[i]['timestamp'] - interactions[i-1]['timestamp']
                time_diffs.append(time_diff)
            
            avg_time_diff = sum(time_diffs) / len(time_diffs)
            if avg_time_diff < 1.0:  # Less than 1 second between traps
                confidence_score += 25
                behavior_patterns.append('rapid_succession')
        
        return {
            'is_bot': confidence_score >= 50,
            'confidence': min(confidence_score, 100),
            'behavior_patterns': behavior_patterns,
            'trap_count': len(interactions),
            'unique_traps': len(unique_traps),
            'first_trap': interactions[0]['timestamp'] if interactions else None,
            'last_trap': interactions[-1]['timestamp'] if interactions else None
        }
    
    def cleanup_old_data(self, max_age_hours=24):
        """Clean up old honeypot data"""
        cutoff_time = time.time() - (max_age_hours * 3600)
        
        # Clean up interactions
        for ip_address in list(self.honeypot_interactions.keys()):
            interactions = self.honeypot_interactions[ip_address]
            recent_interactions = [
                interaction for interaction in interactions
                if interaction['timestamp'] > cutoff_time
            ]
            
            if recent_interactions:
                self.honeypot_interactions[ip_address] = recent_interactions
            else:
                del self.honeypot_interactions[ip_address]
                if ip_address in self.trapped_ips:
                    self.trapped_ips.remove(ip_address)
                if ip_address in self.trap_triggers:
                    del self.trap_triggers[ip_address]
        
        # Clean up decoy sessions
        for session_id in list(self.decoy_sessions.keys()):
            session_data = self.decoy_sessions[session_id]
            if session_data['created'] < cutoff_time:
                del self.decoy_sessions[session_id]
    
    def get_statistics(self):
        """Get honeypot system statistics"""
        current_time = time.time()
        
        # Count recent activity (last hour)
        recent_interactions = 0
        for interactions in self.honeypot_interactions.values():
            recent_interactions += sum(
                1 for interaction in interactions
                if current_time - interaction['timestamp'] < 3600
            )
        
        # Count trap types
        trap_type_counts = defaultdict(int)
        for interactions in self.honeypot_interactions.values():
            for interaction in interactions:
                trap_type_counts[interaction['trap_type']] += 1
        
        return {
            'total_trapped_ips': len(self.trapped_ips),
            'total_interactions': sum(len(interactions) for interactions in self.honeypot_interactions.values()),
            'recent_interactions': recent_interactions,
            'active_decoy_sessions': len(self.decoy_sessions),
            'trap_type_distribution': dict(trap_type_counts),
            'honeypot_paths_count': len(self.honeypot_paths),
            'hidden_fields_count': len(self.hidden_fields),
            'decoy_endpoints_count': len(self.decoy_endpoints)
        }

