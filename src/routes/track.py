from flask import Blueprint, request, redirect, jsonify
from src.models.user import db, TrackingLink, TrackingEvent, AnalyticsSummary
import requests
import json
from datetime import datetime

track_bp = Blueprint('track', __name__)

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def get_user_agent():
    return request.headers.get('User-Agent', '')

def get_geolocation(ip_address):
    """Simple geolocation using a free service"""
    try:
        # Using a free IP geolocation service
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown')
            }
    except:
        pass
    
    return {
        'country': 'Unknown',
        'city': 'Unknown',
        'isp': 'Unknown'
    }

def detect_bot(user_agent, ip_address):
    """Simple bot detection"""
    user_agent_lower = user_agent.lower()
    bot_indicators = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python',
        'requests', 'urllib', 'http', 'api', 'monitor', 'test'
    ]
    
    for indicator in bot_indicators:
        if indicator in user_agent_lower:
            return True
    
    return False

def check_social_referrer():
    """Check if request comes from social media platforms"""
    referrer = request.headers.get('Referer', '').lower()
    social_platforms = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'tiktok.com']
    
    for platform in social_platforms:
        if platform in referrer:
            return {'blocked': True, 'reason': f'social_referrer_{platform.split(".")[0]}'}
    
    return {'blocked': False, 'reason': None}

@track_bp.route('/t/<short_code>')
def track_click(short_code):
    # Get the tracking link
    link = TrackingLink.query.filter_by(short_code=short_code).first()
    if not link:
        return "Link not found", 404
    
    # Collect tracking data
    ip_address = get_client_ip()
    user_agent = get_user_agent()
    timestamp = datetime.utcnow()
    
    # Get geolocation data
    geo_data = get_geolocation(ip_address)
    
    # Bot detection
    is_bot = detect_bot(user_agent, ip_address)
    
    # Social referrer check
    social_check = check_social_referrer()
    
    redirect_status = 'redirected'
    block_reason = None
    
    # Apply blocking rules
    if social_check['blocked']:
        block_reason = social_check['reason']
        redirect_status = 'blocked'
    elif link.bot_blocking_enabled and is_bot:
        block_reason = 'bot_detected'
        redirect_status = 'blocked'
    
    # Record the tracking event
    try:
        event = TrackingEvent(
            link_id=link.id,
            timestamp=timestamp,
            ip_address=ip_address,
            user_agent=user_agent,
            country=geo_data['country'],
            city=geo_data['city'],
            isp=geo_data['isp'],
            redirect_status=redirect_status,
            is_bot=is_bot,
            block_reason=block_reason
        )
        
        db.session.add(event)
        
        # Update analytics summary
        analytics = AnalyticsSummary.query.filter_by(link_id=link.id).first()
        if not analytics:
            analytics = AnalyticsSummary(link_id=link.id)
            db.session.add(analytics)
        
        analytics.total_clicks += 1
        if not is_bot:
            analytics.real_visitors += 1
        if redirect_status == 'blocked':
            analytics.blocked_attempts += 1
        
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Tracking error: {e}")
    
    # Redirect or block
    if redirect_status == 'blocked':
        return "Access blocked", 403
    else:
        return redirect(link.target_url)

@track_bp.route('/p/<link_id>')
def tracking_pixel(link_id):
    """Tracking pixel endpoint"""
    try:
        link = TrackingLink.query.get(link_id)
        if not link:
            # Return 1x1 transparent pixel even if link not found
            return _get_transparent_pixel()
        
        # Collect tracking data
        ip_address = get_client_ip()
        user_agent = get_user_agent()
        timestamp = datetime.utcnow()
        
        # Get geolocation data
        geo_data = get_geolocation(ip_address)
        
        # Bot detection
        is_bot = detect_bot(user_agent, ip_address)
        
        # Social referrer check
        social_check = check_social_referrer()
        
        redirect_status = 'mail_opened'
        block_reason = None
        
        # Apply blocking rules
        if social_check['blocked']:
            block_reason = social_check['reason']
            redirect_status = 'blocked'
        elif link.bot_blocking_enabled and is_bot:
            block_reason = 'bot_detected'
            redirect_status = 'blocked'
        
        # Record the tracking event
        event = TrackingEvent(
            link_id=link.id,
            timestamp=timestamp,
            ip_address=ip_address,
            user_agent=user_agent,
            country=geo_data['country'],
            city=geo_data['city'],
            isp=geo_data['isp'],
            redirect_status=redirect_status,
            is_bot=is_bot,
            block_reason=block_reason
        )
        
        db.session.add(event)
        
        # Update analytics summary
        analytics = AnalyticsSummary.query.filter_by(link_id=link.id).first()
        if not analytics:
            analytics = AnalyticsSummary(link_id=link.id)
            db.session.add(analytics)
        
        analytics.total_clicks += 1
        if not is_bot:
            analytics.real_visitors += 1
        if redirect_status == 'blocked':
            analytics.blocked_attempts += 1
        
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Pixel tracking error: {e}")
    
    return _get_transparent_pixel()

def _get_transparent_pixel():
    """Return a 1x1 transparent PNG pixel"""
    from flask import Response
    import base64
    
    # 1x1 transparent PNG
    pixel_data = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==')
    
    response = Response(pixel_data, mimetype='image/png')
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

