"""
Browser verification endpoint for anti-bot protection
"""

from flask import Blueprint, request, jsonify, session
from src.security.antibot import AdvancedAntiBotProtection
import time
import hashlib
import json

browser_verify_bp = Blueprint('browser_verify', __name__)

@browser_verify_bp.route('/api/verify-browser', methods=['POST'])
def verify_browser():
    """Verify browser fingerprint and issue verification token"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        # Validate fingerprint data
        required_fields = ['screen', 'timezone', 'language', 'platform', 'canvas', 'timestamp', 'challenge']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Incomplete fingerprint'}), 400
        
        # Verify challenge timing (should be recent)
        client_timestamp = data.get('timestamp', 0)
        server_time = int(time.time() * 1000)  # Convert to milliseconds
        time_diff = abs(server_time - client_timestamp)
        
        if time_diff > 30000:  # 30 seconds tolerance
            return jsonify({'error': 'Challenge expired'}), 400
        
        # Verify canvas fingerprint (basic check)
        canvas_data = data.get('canvas', '')
        if not canvas_data.startswith('data:image/png;base64,'):
            return jsonify({'error': 'Invalid canvas data'}), 400
        
        # Create fingerprint hash
        fingerprint_string = json.dumps(data, sort_keys=True)
        fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
        
        # Generate verification token
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()
        
        antibot = AdvancedAntiBotProtection()
        verification_token = antibot.generate_challenge_token(ip_address)
        
        # Store verification in session
        session['browser_verified'] = verification_token
        session['fingerprint_hash'] = fingerprint_hash
        session['verification_time'] = time.time()
        
        return jsonify({
            'status': 'verified',
            'token': verification_token
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Verification failed'}), 500

@browser_verify_bp.route('/api/check-verification', methods=['GET'])
def check_verification():
    """Check if browser is verified"""
    verification_token = session.get('browser_verified')
    verification_time = session.get('verification_time', 0)
    
    # Check if verification exists and is not expired (1 hour)
    if verification_token and time.time() - verification_time < 3600:
        return jsonify({'verified': True}), 200
    else:
        return jsonify({'verified': False}), 200

