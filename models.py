from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    active = db.Column(db.Boolean, nullable=False, default=True)
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    approval_status = db.Column(db.String(20), nullable=False, default="approved")
    security_question = db.Column(db.String(255), nullable=True)
    security_answer_hash = db.Column(db.String(255), nullable=True)
    captcha_failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    is_banned = db.Column(db.Boolean, nullable=False, default=False)
    pending_admin_review = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    loans = db.relationship("Loan", back_populates="requester", foreign_keys="Loan.requester_id")
    incidents = db.relationship("Incident", back_populates="reporter", foreign_keys="Incident.reporter_id")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def set_security_answer(self, answer: str) -> None:
        self.security_answer_hash = generate_password_hash(answer.strip().lower())

    def check_security_answer(self, answer: str) -> bool:
        if not self.security_answer_hash:
            return False
        return check_password_hash(self.security_answer_hash, answer.strip().lower())


class Equipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    asset_tag = db.Column(db.String(60), unique=True, nullable=False)
    category = db.Column(db.String(60), nullable=False)
    location = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="available")
    criticality = db.Column(db.String(20), nullable=False, default="medium")
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    loans = db.relationship("Loan", back_populates="equipment")
    incidents = db.relationship("Incident", back_populates="equipment")


class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    equipment_id = db.Column(db.Integer, db.ForeignKey("equipment.id"), nullable=False)
    purpose = db.Column(db.String(255), nullable=False)
    requested_days = db.Column(db.Integer, nullable=False, default=1)
    due_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="requested")
    rejection_reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    requester = db.relationship("User", back_populates="loans", foreign_keys=[requester_id])
    equipment = db.relationship("Equipment", back_populates="loans")


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    equipment_id = db.Column(db.Integer, db.ForeignKey("equipment.id"), nullable=True)
    title = db.Column(db.String(120), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="low")
    description = db.Column(db.Text, nullable=False)
    technical_response = db.Column(db.Text, nullable=True)
    responded_by_email = db.Column(db.String(120), nullable=True)
    responded_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="open")
    pending_technician_review = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    reporter = db.relationship("User", back_populates="incidents", foreign_keys=[reporter_id])
    equipment = db.relationship("Equipment", back_populates="incidents")


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_email = db.Column(db.String(120), nullable=False)
    action = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
