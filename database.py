from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    salt = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), nullable=False) # Admin, Doctor, Patient
    totp_secret = db.Column(db.String(32), nullable=True) # For MFA

class MedicalRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    content_hash = db.Column(db.String(64), nullable=False) # SHA-256
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

# Access Control List (Stored in DB for Matrix demonstration)
class AccessControl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), nullable=False)
    resource = db.Column(db.String(50), nullable=False)
    permission = db.Column(db.String(10), nullable=False) # READ, WRITE, DELETE

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    base64_content = db.Column(db.Text, nullable=False) # Long text for Base64

