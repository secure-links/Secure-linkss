"""
Dynamic robots.txt handler with additional security features
"""

from flask import Blueprint, request, Response, current_app
import time
import hashlib
from datetime import datetime

robots_bp = Blueprint('robots', __name__)

@robots_bp.route('/robots.txt')
def robots_txt():
    """Serve robots.txt with dynamic content based on request analysis"""
    
    # Get client information
    user_agent = request.headers.get('User-Agent', '').lower()
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()
    
    # Analyze request for suspicious patterns
    suspicious_indicators = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 
        'python', 'java', 'go', 'rust', 'selenium', 'phantom',
        'headless', 'automation', 'test', 'monitor', 'scan', 'probe'
    ]
    
    is_suspicious = any(indicator in user_agent for indicator in suspicious_indicators)
    
    # Base robots.txt content
    base_content = """# Robots.txt - Link Tracker Service
User-agent: *
Disallow: /api/
Disallow: /admin/
Disallow: /private/
Disallow: /track/
Disallow: /t/
Disallow: /redirect/
Disallow: /r/
Crawl-delay: 10

# Search engines
User-agent: Googlebot
Disallow: /api/
Disallow: /admin/
Disallow: /private/
Allow: /
Crawl-delay: 5

User-agent: Bingbot
Disallow: /api/
Disallow: /admin/
Disallow: /private/
Allow: /
Crawl-delay: 8
"""
    
    # If suspicious, add more restrictive rules
    if is_suspicious:
        restrictive_content = """
# Detected automated access - Enhanced restrictions
User-agent: *
Disallow: /
Crawl-delay: 86400

# Block common scraping tools
User-agent: wget
Disallow: /

User-agent: curl
Disallow: /

User-agent: python-requests
Disallow: /

User-agent: scrapy
Disallow: /

User-agent: selenium
Disallow: /

User-agent: phantomjs
Disallow: /

# Block AI training bots
User-agent: ChatGPT-User
Disallow: /

User-agent: GPTBot
Disallow: /

User-agent: Claude-Web
Disallow: /

User-agent: CCBot
Disallow: /

# Block aggressive crawlers
User-agent: AhrefsBot
Disallow: /

User-agent: MJ12bot
Disallow: /

User-agent: SemrushBot
Disallow: /

User-agent: BLEXBot
Disallow: /
"""
        content = base_content + restrictive_content
    else:
        content = base_content
    
    # Add timestamp and fingerprint for tracking
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    fingerprint = hashlib.md5(f"{ip_address}{user_agent}{timestamp}".encode()).hexdigest()[:8]
    
    content += f"""
# Generated: {timestamp}
# Request ID: {fingerprint}
"""
    
    # Log the request for analysis
    current_app.logger.info(f"robots.txt requested by {ip_address} - UA: {user_agent[:100]} - Suspicious: {is_suspicious}")
    
    # Return with appropriate headers
    response = Response(content, mimetype='text/plain')
    response.headers['Cache-Control'] = 'public, max-age=3600'  # Cache for 1 hour
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    
    return response

@robots_bp.route('/sitemap.xml')
def sitemap_xml():
    """Serve a minimal sitemap or redirect suspicious requests"""
    
    user_agent = request.headers.get('User-Agent', '').lower()
    
    # Check if this looks like a legitimate search engine
    legitimate_bots = ['googlebot', 'bingbot', 'slurp', 'duckduckbot']
    is_legitimate = any(bot in user_agent for bot in legitimate_bots)
    
    if not is_legitimate:
        # Return empty sitemap for suspicious requests
        content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
</urlset>"""
    else:
        # Return basic sitemap for legitimate crawlers
        content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://yourdomain.com/</loc>
        <lastmod>2024-01-01</lastmod>
        <changefreq>monthly</changefreq>
        <priority>1.0</priority>
    </url>
</urlset>"""
    
    response = Response(content, mimetype='application/xml')
    response.headers['Cache-Control'] = 'public, max-age=86400'  # Cache for 24 hours
    
    return response

@robots_bp.route('/.well-known/security.txt')
def security_txt():
    """Serve security.txt to appear legitimate while providing minimal info"""
    
    content = """Contact: security@example.com
Expires: 2025-12-31T23:59:59.000Z
Preferred-Languages: en
Canonical: https://yourdomain.com/.well-known/security.txt
"""
    
    response = Response(content, mimetype='text/plain')
    response.headers['Cache-Control'] = 'public, max-age=86400'
    
    return response

