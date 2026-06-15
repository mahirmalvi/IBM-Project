from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), default='user') # 'user' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    scans = db.relationship('ScanHistory', backref='user', lazy=True, cascade="all, delete-orphan")
    quizzes = db.relationship('QuizResult', backref='user', lazy=True, cascade="all, delete-orphan")
    admin_logs = db.relationship('AdminLog', backref='admin', lazy=True, cascade="all, delete-orphan", foreign_keys='AdminLog.admin_id')
    password_checks = db.relationship('PasswordStrengthCheck', backref='user', lazy=True, cascade="all, delete-orphan")
    passwords_generated = db.relationship('PasswordGenerated', backref='user', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=True, index=True)
    url = db.Column(db.Text, nullable=False)
    prediction = db.Column(db.String(10), nullable=False) # 'Safe' or 'Phishing'
    confidence_score = db.Column(db.Float, nullable=False) # e.g. 95.5
    risk_score = db.Column(db.Integer, nullable=False) # 0 to 100
    features = db.Column(db.Text, nullable=False) # JSON encoded features dictionary
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ScanHistory {self.url[:30]}... [{self.prediction}]>"


class QuizResult(db.Model):
    __tablename__ = 'quiz_results'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    certificate_code = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f"<QuizResult User {self.user_id}: {self.score}/{self.total_questions}>"


class AdminLog(db.Model):
    __tablename__ = 'admin_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    action = db.Column(db.String(255), nullable=False)
    target_user_id = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<AdminLog Admin {self.admin_id} - {self.action}>"


class PasswordStrengthCheck(db.Model):
    __tablename__ = 'password_strength_checks'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False)
    strength = db.Column(db.String(20), nullable=False) # 'Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<PasswordStrengthCheck User {self.user_id}: {self.strength} ({self.score}/100)>"


class PasswordGenerated(db.Model):
    __tablename__ = 'passwords_generated'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    length = db.Column(db.Integer, nullable=False)
    entropy = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<PasswordGenerated User {self.user_id}: length {self.length}, entropy {self.entropy:.1f} bits>"

