"""
Advanced IP Reputation and Threat Intelligence System
In-house implementation without third-party dependencies
"""

import ipaddress
import time
import json
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
import re

class IPIntelligenceEngine:
    def __init__(self):
        self.ip_reputation_cache = {}
        self.threat_patterns = {}
        self.geo_blocks = set()
        self.suspicious_networks = set()
        self.whitelist_ips = set()
        self.blacklist_ips = set()
        self.ip_activity_log = defaultdict(list)
        
        # Initialize known malicious IP ranges and patterns
        self._initialize_threat_intelligence()
    
    def _initialize_threat_intelligence(self):
        """Initialize built-in threat intelligence data"""
        
        # Known malicious IP ranges (CIDR notation)
        self.suspicious_networks.update([
            # Tor exit nodes (sample ranges)
            '185.220.100.0/22',
            '185.220.101.0/24',
            '199.87.154.0/24',
            
            # Known VPN/Proxy ranges
            '5.2.64.0/20',
            '5.2.80.0/20',
            '31.31.72.0/21',
            '37.120.128.0/19',
            '46.166.128.0/18',
            '62.102.148.0/22',
            '77.247.181.0/24',
            '78.142.16.0/20',
            '85.17.30.0/23',
            '91.121.0.0/16',
            '94.242.246.0/24',
            '95.85.0.0/18',
            '109.201.133.0/24',
            '176.10.104.0/21',
            '176.10.116.0/22',
            '185.86.148.0/22',
            '188.214.128.0/17',
            '192.42.116.0/22',
            '198.98.48.0/20',
            '199.195.248.0/21',
            
            # Cloud hosting ranges often used by bots
            '13.107.42.0/24',
            '40.76.0.0/14',
            '52.96.0.0/12',
            '104.40.0.0/13',
            '137.116.0.0/16',
            '168.61.0.0/16',
            '207.46.0.0/16',
            
            # Known bot hosting networks
            '5.9.0.0/16',
            '78.46.0.0/15',
            '136.243.0.0/16',
            '144.76.0.0/16',
            '148.251.0.0/16',
            '176.9.0.0/16',
            '188.40.0.0/16',
            '213.239.192.0/18',
        ])
        
        # Threat patterns for IP analysis
        self.threat_patterns = {
            'datacenter_ranges': [
                # Major cloud providers and datacenters
                '3.0.0.0/8',      # Amazon AWS
                '13.0.0.0/8',     # Amazon AWS
                '15.0.0.0/8',     # Amazon AWS
                '18.0.0.0/8',     # Amazon AWS
                '34.0.0.0/8',     # Google Cloud
                '35.0.0.0/8',     # Google Cloud
                '104.154.0.0/15', # Google Cloud
                '130.211.0.0/16', # Google Cloud
                '146.148.0.0/17', # Google Cloud
                '162.216.148.0/22', # Google Cloud
                '162.222.176.0/21', # Google Cloud
                '173.255.112.0/20', # Google Cloud
                '199.192.112.0/22', # Google Cloud
                '199.223.232.0/21', # Google Cloud
                '23.20.0.0/14',   # Amazon AWS
                '50.16.0.0/15',   # Amazon AWS
                '50.19.0.0/16',   # Amazon AWS
                '52.0.0.0/11',    # Microsoft Azure
                '13.64.0.0/11',   # Microsoft Azure
                '20.0.0.0/6',     # Microsoft Azure
                '40.64.0.0/10',   # Microsoft Azure
                '65.52.0.0/14',   # Microsoft Azure
                '70.37.0.0/16',   # Microsoft Azure
                '94.245.64.0/18', # Microsoft Azure
                '103.4.96.0/22',  # Microsoft Azure
                '103.25.156.0/22', # Microsoft Azure
                '104.40.0.0/13',  # Microsoft Azure
                '134.170.0.0/16', # Microsoft Azure
                '138.91.0.0/16',  # Microsoft Azure
                '157.55.0.0/16',  # Microsoft Azure
                '168.61.0.0/16',  # Microsoft Azure
                '168.62.0.0/15',  # Microsoft Azure
                '191.232.0.0/13', # Microsoft Azure
                '199.30.16.0/20', # Microsoft Azure
                '207.46.0.0/16',  # Microsoft Azure
            ],
            'proxy_indicators': [
                # Common proxy/VPN service ranges
                '5.2.64.0/20',
                '31.31.72.0/21',
                '37.120.128.0/19',
                '46.166.128.0/18',
                '62.102.148.0/22',
                '77.247.181.0/24',
                '78.142.16.0/20',
                '85.17.30.0/23',
                '91.121.0.0/16',
                '94.242.246.0/24',
                '95.85.0.0/18',
                '109.201.133.0/24',
                '176.10.104.0/21',
                '176.10.116.0/22',
                '185.86.148.0/22',
                '188.214.128.0/17',
                '192.42.116.0/22',
                '198.98.48.0/20',
                '199.195.248.0/21',
            ]
        }
        
        # Geographic blocks (country codes for high-risk regions)
        # Note: This is a simplified approach - in production you'd use GeoIP databases
        self.high_risk_asn_patterns = [
            # Patterns that often indicate hosting/VPN services
            r'.*hosting.*',
            r'.*server.*',
            r'.*datacenter.*',
            r'.*cloud.*',
            r'.*vps.*',
            r'.*dedicated.*',
            r'.*colocation.*',
            r'.*vpn.*',
            r'.*proxy.*',
            r'.*tunnel.*',
        ]
    
    def analyze_ip_reputation(self, ip_address):
        """Comprehensive IP reputation analysis"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            reputation_score = 0
            risk_factors = []
            
            # Check if IP is in suspicious networks
            if self._is_in_suspicious_network(ip_address):
                reputation_score += 50
                risk_factors.append('suspicious_network')
            
            # Check if IP is in datacenter ranges
            if self._is_datacenter_ip(ip_address):
                reputation_score += 30
                risk_factors.append('datacenter_hosting')
            
            # Check if IP is in proxy/VPN ranges
            if self._is_proxy_ip(ip_address):
                reputation_score += 40
                risk_factors.append('proxy_vpn')
            
            # Check IP activity patterns
            activity_score = self._analyze_ip_activity(ip_address)
            reputation_score += activity_score
            if activity_score > 20:
                risk_factors.append('suspicious_activity')
            
            # Check for rapid IP changes (potential bot farm)
            if self._detect_ip_hopping(ip_address):
                reputation_score += 25
                risk_factors.append('ip_hopping')
            
            # Private/Reserved IP analysis
            if ip_obj.is_private or ip_obj.is_reserved:
                reputation_score += 60
                risk_factors.append('private_reserved')
            
            # Loopback and multicast
            if ip_obj.is_loopback or ip_obj.is_multicast:
                reputation_score += 70
                risk_factors.append('invalid_source')
            
            # Cache the result
            self.ip_reputation_cache[ip_address] = {
                'score': min(reputation_score, 100),
                'risk_factors': risk_factors,
                'timestamp': time.time(),
                'classification': self._classify_risk_level(reputation_score)
            }
            
            return self.ip_reputation_cache[ip_address]
            
        except ValueError:
            # Invalid IP address
            return {
                'score': 100,
                'risk_factors': ['invalid_ip'],
                'timestamp': time.time(),
                'classification': 'high_risk'
            }
    
    def _is_in_suspicious_network(self, ip_address):
        """Check if IP is in known suspicious networks"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            for network_cidr in self.suspicious_networks:
                if ip_obj in ipaddress.ip_network(network_cidr):
                    return True
        except (ValueError, ipaddress.AddressValueError):
            pass
        return False
    
    def _is_datacenter_ip(self, ip_address):
        """Check if IP belongs to datacenter/hosting ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            for network_cidr in self.threat_patterns['datacenter_ranges']:
                if ip_obj in ipaddress.ip_network(network_cidr):
                    return True
        except (ValueError, ipaddress.AddressValueError):
            pass
        return False
    
    def _is_proxy_ip(self, ip_address):
        """Check if IP belongs to proxy/VPN ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            for network_cidr in self.threat_patterns['proxy_indicators']:
                if ip_obj in ipaddress.ip_network(network_cidr):
                    return True
        except (ValueError, ipaddress.AddressValueError):
            pass
        return False
    
    def _analyze_ip_activity(self, ip_address):
        """Analyze IP activity patterns for suspicious behavior"""
        activity_score = 0
        current_time = time.time()
        
        # Get recent activity for this IP
        recent_activity = [
            timestamp for timestamp in self.ip_activity_log[ip_address]
            if current_time - timestamp < 3600  # Last hour
        ]
        
        # High frequency requests
        if len(recent_activity) > 100:
            activity_score += 30
        elif len(recent_activity) > 50:
            activity_score += 20
        elif len(recent_activity) > 20:
            activity_score += 10
        
        # Check for burst patterns (many requests in short time)
        if len(recent_activity) >= 10:
            time_diffs = [
                recent_activity[i] - recent_activity[i-1]
                for i in range(1, len(recent_activity))
            ]
            avg_interval = sum(time_diffs) / len(time_diffs)
            
            # Very regular intervals (bot-like)
            if avg_interval < 1.0:  # Less than 1 second average
                activity_score += 25
            elif avg_interval < 5.0:  # Less than 5 seconds average
                activity_score += 15
        
        return min(activity_score, 50)
    
    def _detect_ip_hopping(self, ip_address):
        """Detect if this IP is part of a rapidly changing IP pattern"""
        # This would typically involve analyzing session data
        # For now, we'll implement a basic version
        current_time = time.time()
        
        # Check if we've seen similar IPs recently (same /24 network)
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            network = ipaddress.ip_network(f"{ip_obj}/24", strict=False)
            
            similar_ips = 0
            for cached_ip in self.ip_reputation_cache:
                try:
                    cached_ip_obj = ipaddress.ip_address(cached_ip)
                    if cached_ip_obj in network:
                        cache_time = self.ip_reputation_cache[cached_ip]['timestamp']
                        if current_time - cache_time < 300:  # Last 5 minutes
                            similar_ips += 1
                except ValueError:
                    continue
            
            return similar_ips > 5  # More than 5 IPs from same /24 in 5 minutes
            
        except ValueError:
            return False
    
    def _classify_risk_level(self, score):
        """Classify risk level based on reputation score"""
        if score >= 80:
            return 'high_risk'
        elif score >= 60:
            return 'medium_risk'
        elif score >= 40:
            return 'low_risk'
        else:
            return 'clean'
    
    def log_ip_activity(self, ip_address):
        """Log IP activity for pattern analysis"""
        current_time = time.time()
        self.ip_activity_log[ip_address].append(current_time)
        
        # Keep only recent activity (last 24 hours)
        cutoff_time = current_time - 86400
        self.ip_activity_log[ip_address] = [
            timestamp for timestamp in self.ip_activity_log[ip_address]
            if timestamp > cutoff_time
        ]
    
    def add_to_whitelist(self, ip_address):
        """Add IP to whitelist"""
        self.whitelist_ips.add(ip_address)
    
    def add_to_blacklist(self, ip_address):
        """Add IP to blacklist"""
        self.blacklist_ips.add(ip_address)
    
    def is_whitelisted(self, ip_address):
        """Check if IP is whitelisted"""
        return ip_address in self.whitelist_ips
    
    def is_blacklisted(self, ip_address):
        """Check if IP is blacklisted"""
        return ip_address in self.blacklist_ips
    
    def get_ip_intelligence(self, ip_address):
        """Get comprehensive intelligence report for an IP"""
        # Log the activity
        self.log_ip_activity(ip_address)
        
        # Check whitelist/blacklist first
        if self.is_whitelisted(ip_address):
            return {
                'status': 'whitelisted',
                'action': 'allow',
                'score': 0,
                'risk_factors': [],
                'classification': 'trusted'
            }
        
        if self.is_blacklisted(ip_address):
            return {
                'status': 'blacklisted',
                'action': 'block',
                'score': 100,
                'risk_factors': ['blacklisted'],
                'classification': 'blocked'
            }
        
        # Get reputation analysis
        reputation = self.analyze_ip_reputation(ip_address)
        
        # Determine action based on risk level
        if reputation['classification'] == 'high_risk':
            action = 'block'
        elif reputation['classification'] == 'medium_risk':
            action = 'challenge'
        else:
            action = 'allow'
        
        return {
            'status': 'analyzed',
            'action': action,
            'score': reputation['score'],
            'risk_factors': reputation['risk_factors'],
            'classification': reputation['classification'],
            'timestamp': reputation['timestamp']
        }
    
    def update_threat_intelligence(self, new_threats):
        """Update threat intelligence with new data"""
        if 'suspicious_networks' in new_threats:
            self.suspicious_networks.update(new_threats['suspicious_networks'])
        
        if 'threat_patterns' in new_threats:
            for category, patterns in new_threats['threat_patterns'].items():
                if category in self.threat_patterns:
                    self.threat_patterns[category].extend(patterns)
                else:
                    self.threat_patterns[category] = patterns
    
    def get_statistics(self):
        """Get intelligence engine statistics"""
        current_time = time.time()
        
        # Count recent activities
        recent_ips = 0
        total_requests = 0
        
        for ip, activities in self.ip_activity_log.items():
            recent_activities = [
                timestamp for timestamp in activities
                if current_time - timestamp < 3600
            ]
            if recent_activities:
                recent_ips += 1
                total_requests += len(recent_activities)
        
        return {
            'total_tracked_ips': len(self.ip_activity_log),
            'recent_active_ips': recent_ips,
            'recent_requests': total_requests,
            'whitelisted_ips': len(self.whitelist_ips),
            'blacklisted_ips': len(self.blacklist_ips),
            'suspicious_networks': len(self.suspicious_networks),
            'threat_patterns': len(self.threat_patterns),
            'cache_size': len(self.ip_reputation_cache)
        }

