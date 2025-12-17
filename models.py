from flask_sqlalchemy import SQLAlchemy
from datetime import date

db = SQLAlchemy()

# --- Repository / Master Data ---
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='trial') # 'admin', 'pro', 'trial'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True) # Blocked users
    pro_expiration_date = db.Column(db.Date, nullable=True) # Date expiration PRO
    
    # Relationships (Cascading Data Deletion)
    categories = db.relationship('MasterCategory', backref='owner', cascade="all, delete-orphan", lazy=True)
    daily_entries = db.relationship('DailyEntry', backref='owner', cascade="all, delete-orphan", lazy=True)
    history_entries = db.relationship('HistoryEntry', backref='owner', cascade="all, delete-orphan", lazy=True)
    pro_requests = db.relationship('ProRequest', backref='user', foreign_keys='[ProRequest.user_id]', cascade="all, delete-orphan", lazy=True)

# --- PRO Upgrade Requests ---
class ProRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    duration_years = db.Column(db.Integer, nullable=False) # 1 ou 5
    payment_method = db.Column(db.String(50), nullable=False) # 'virement', 'd17', 'flouci'
    status = db.Column(db.String(50), default='EN_ATTENTE_PAIEMENT') # EN_ATTENTE_PAIEMENT, PAIEMENT_EN_VERIFICATION, APPROUVEE, REFUSEE
    proof_filename = db.Column(db.String(255), nullable=True) # Nom fichier justificatif
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    validated_at = db.Column(db.DateTime, nullable=True)
    validated_by_admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

# --- Repository / Master Data ---
class MasterCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False) # Removed unique=True global constraint for multi-tenancy (enforced per user logic instead)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tasks = db.relationship('MasterTask', backref='category', cascade="all, delete-orphan", lazy=True)

class MasterTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('master_category.id'), nullable=False)

# --- Daily Workflow ---
class DailyEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_name = db.Column(db.String(100)) # Snapshot
    task_name = db.Column(db.String(200))     # Snapshot
    impact_score = db.Column(db.Integer)
    risk_score = db.Column(db.Integer)
    total_score = db.Column(db.Integer) # Calculated
    planified_date = db.Column(db.Date)
    finish_date = db.Column(db.Date, nullable=True)
    proceed_rate = db.Column(db.Integer) # 0-100
    numb_minutes = db.Column(db.Integer)
    comment = db.Column(db.Text)
    # pin_mode: 'none', 'recurring', 'continue'
    # 'recurring': Keep Task+Scores, Reset Progress
    # 'continue': Keep Everything
    pin_mode = db.Column(db.String(20), default='none')

# --- History ---
class HistoryEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_name = db.Column(db.String(100))
    task_name = db.Column(db.String(200))
    impact_score = db.Column(db.Integer)
    risk_score = db.Column(db.Integer)
    total_score = db.Column(db.Integer)
    planified_date = db.Column(db.Date)
    finish_date = db.Column(db.Date, nullable=True)
    proceed_rate = db.Column(db.Integer)
    numb_minutes = db.Column(db.Integer)
    comment = db.Column(db.Text)
    is_pinned = db.Column(db.Boolean)
    date_of_the_day = db.Column(db.Date, default=date.today)
