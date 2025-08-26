from CTFd.models import db
from datetime import datetime, UTC

class DiscordRegistrations(db.Model):
    __tablename__ = "discord_registrations"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    discord_id = db.Column(db.String(64), nullable=False)
    code = db.Column(db.String(32), nullable=False)
    requested_at = db.Column(db.DateTime, default=datetime.now(UTC))
