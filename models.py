from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_superadmin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    requests = db.relationship(
        'AccessRequest', backref='user', lazy='dynamic',
        cascade='all, delete-orphan',
        foreign_keys='AccessRequest.user_id'
    )
    logs = db.relationship('ConsoleLog', backref='user', lazy='dynamic',
                           cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class AccessRequest(db.Model):
    __tablename__ = 'access_requests'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    server_name = db.Column(db.String(100), nullable=False)
    access_duration = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    review_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    reviewer = db.relationship(
        'User', backref='reviewed_requests', lazy='joined',
        foreign_keys=[reviewed_by]
    )
    photos = db.relationship('Photo', backref='request', lazy='dynamic',
                             cascade='all, delete-orphan')

    @property
    def status_badge(self):
        badges = {'pending': 'warning', 'approved': 'success', 'rejected': 'danger'}
        return badges.get(self.status, 'secondary')

    def __repr__(self):
        return f'<AccessRequest {self.id} - {self.status}>'


class Photo(db.Model):
    __tablename__ = 'photos'

    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('access_requests.id'),
                           nullable=False, index=True)
    photo_type = db.Column(db.String(10), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Photo {self.photo_type} for Request {self.request_id}>'


class ConsoleLog(db.Model):
    __tablename__ = 'console_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    request_id = db.Column(db.Integer, db.ForeignKey('access_requests.id'),
                           nullable=True, index=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    request_ref = db.relationship('AccessRequest', backref='logs', lazy='joined')

    def __repr__(self):
        return f'<ConsoleLog {self.action} by User {self.user_id}>'


class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    request_id = db.Column(db.Integer, db.ForeignKey('access_requests.id'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default='info')
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='notifications', lazy='joined',
                           foreign_keys=[user_id])

    def __repr__(self):
        return f'<Notification {self.title} for User {self.user_id}>'
