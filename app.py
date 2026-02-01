from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from database import db, User, MedicalRecord, AccessLog, Document
from crypto_utils import hash_password, verify_password, encrypt_data, decrypt_data, hash_data
import pyotp
import os
import base64
from functools import wraps
from werkzeug.utils import secure_filename

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev-secret-key-change-this-to-something-secure'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hospital_secure.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
             pwd_hash, salt = hash_password('admin123')
             admin = User(username='admin', password_hash=pwd_hash, salt=salt, role='Admin', totp_secret=pyotp.random_base32())
             db.session.add(admin)
             db.session.commit()
             print("Admin user created (user: admin, pass: admin123)")

    return app

app = create_app()

# --- Authorization Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_role(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in allowed_roles:
                abort(403) # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def home():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        pwd_hash, salt = hash_password(password)
        totp_secret = pyotp.random_base32()
        
        new_user = User(
            username=username, 
            password_hash=pwd_hash, 
            salt=salt, 
            role=role,
            totp_secret=totp_secret
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and verify_password(user.password_hash, user.salt, password):
            session['pre_2fa_user_id'] = user.id
            totp = pyotp.TOTP(user.totp_secret)
            current_otp = totp.now()
            print(f" [MFA] OTP for {user.username}: {current_otp}")
            return redirect(url_for('otp_verify'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/otp-verify', methods=['GET', 'POST'])
def otp_verify():
    if 'pre_2fa_user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_input = request.form.get('otp')
        user_id = session.get('pre_2fa_user_id')
        user = User.query.get(user_id)
        
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(otp_input, valid_window=1): 
            session.pop('pre_2fa_user_id', None)
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            flash(f'Welcome back, {user.username} (Role: {user.role})', 'success')
            
            log = AccessLog(user_id=user.id, action="Login Successful")
            db.session.add(log)
            db.session.commit()
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP', 'error')
            
    return render_template('otp.html')

@app.route('/dashboard')
@login_required
def dashboard():
    role = session['role']
    logs = []
    records_display = []
    documents = []

    if role == 'Admin':
        logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).all()
    
    elif role == 'Doctor':
        records = MedicalRecord.query.filter_by(doctor_id=session['user_id']).all()
        for r in records:
            decrypted = decrypt_data(r.encrypted_content)
            current_hash = hash_data(decrypted)
            records_display.append({
                'id': r.id,
                'timestamp': r.timestamp,
                'encrypted_preview': str(r.encrypted_content)[:20],
                'decrypted_content': decrypted,
                'integrity_check': current_hash == r.content_hash
            })

    elif role == 'Patient':
        records = MedicalRecord.query.filter_by(patient_id=session['user_id']).all()
        for r in records:
            decrypted = decrypt_data(r.encrypted_content)
            current_hash = hash_data(decrypted)
            records_display.append({
                'id': r.id,
                'timestamp': r.timestamp,
                'encrypted_preview': str(r.encrypted_content)[:20],
                'decrypted_content': decrypted,
                'integrity_check': current_hash == r.content_hash
            })
        
        # Patients can see their uploads
        documents = Document.query.filter_by(owner_id=session['user_id']).all()

    return render_template('dashboard.html', logs=logs, records=records_display, documents=documents)

@app.route('/create_record', methods=['POST'])
@login_required
@check_role(['Doctor'])
def create_record():
    patient_username = request.form.get('patient_username')
    content = request.form.get('content')
    
    patient = User.query.filter_by(username=patient_username, role='Patient').first()
    if not patient:
        flash('Patient not found!', 'error')
        return redirect(url_for('dashboard'))
    
    encrypted_blob = encrypt_data(content)
    integrity_hash = hash_data(content)
    
    new_record = MedicalRecord(
        patient_id=patient.id,
        doctor_id=session['user_id'],
        encrypted_content=encrypted_blob,
        content_hash=integrity_hash
    )
    
    db.session.add(new_record)
    log = AccessLog(user_id=session['user_id'], action=f"Created Record for {patient.username}")
    db.session.add(log)
    
    db.session.commit()
    flash('Medical Record Created & Encrypted Successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/upload_document', methods=['POST'])
@login_required
@check_role(['Patient'])
def upload_document():
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('dashboard'))

    if file:
        filename = secure_filename(file.filename)
        # Encoding: Convert file to Base64
        file_content = file.read()
        b64_content = base64.b64encode(file_content).decode('utf-8')
        
        new_doc = Document(owner_id=session['user_id'], filename=filename, base64_content=b64_content)
        db.session.add(new_doc)
        db.session.commit()
        
        flash('Document uploaded and Base64 encoded successfully!', 'success')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
