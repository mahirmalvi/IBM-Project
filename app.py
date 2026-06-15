import os
import json
import pickle
import csv
import io
import uuid
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, 
    url_for, flash, session, jsonify, send_file, make_response
)
import bcrypt
from flask_wtf.csrf import CSRFProtect
import logging

# Custom Modules
from config import Config
from models import db, User, ScanHistory, QuizResult, AdminLog, PasswordStrengthCheck, PasswordGenerated
from ml_module.features import get_feature_list, extract_features, calculate_heuristic_risk
from utils.db_helper import init_db
from utils.pdf_generator import generate_scan_pdf

app = Flask(__name__)
app.config.from_object(Config)

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Configure Logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
)

# --- Bcrypt Hashing Helpers ---
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(pw_hash: str, password: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), pw_hash.encode('utf-8'))
    except Exception:
        return False

# Initialize Database
db.init_app(app)
init_db(app, db)

# Load ML Model
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ml_module', 'phishing_model.pkl')
phishing_model = None

try:
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, 'rb') as f:
            phishing_model = pickle.load(f)
        print("Machine Learning Model loaded successfully.")
    else:
        print("WARNING: ML Model file not found. URL scanner will run in heuristic mode only.")
except Exception as e:
    print(f"ERROR: Could not load ML model: {e}. URL scanner running in heuristic mode.")


# --- Authentication Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Access denied. Administrator privileges required.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function


# --- Public / Awareness Routes ---

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        # In a real app, send email or write to a support database
        print(f"Contact message received from {name} ({email}) regarding '{subject}': {message}")
        flash('Thank you for reaching out! Your feedback/inquiry has been logged.', 'success')
        return redirect(url_for('home'))
    return render_template('contact.html')

@app.route('/articles')
def articles():
    return render_template('articles.html')

@app.route('/developer')
def developer():
    return render_template('developer.html')


# --- Authentication System Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password')
        
        if not username or not email or not password:
            flash('All registration fields are required.', 'danger')
            return redirect(url_for('register'))
            
        # Check if user exists
        existing_username = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        
        if existing_username or existing_email:
            flash('Username or Email already registered.', 'danger')
            return redirect(url_for('register'))
            
        # Create user
        new_user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role='user'
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please sign in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username_input = request.form.get('username', '').strip()
        password = request.form.get('password')
        
        user = User.query.filter((User.username == username_input) | (User.email == username_input)).first()
        
        if user and check_password(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            flash(f"Welcome back, {user.username}!", 'success')
            
            # Audit log login for admin
            if user.role == 'admin':
                log_item = AdminLog(
                    admin_id=user.id,
                    action=f"Administrator '{user.username}' logged in.",
                    target_user_id=None,
                    ip_address=request.remote_addr
                )
                db.session.add(log_item)
                db.session.commit()
                return redirect(url_for('admin_dashboard'))
                
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
            
        flash('Invalid username/email or password.', 'danger')
        return redirect(url_for('login'))
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))


# --- URL Scanning Processing API Endpoint ---

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"success": False, "error": "URL address cannot be blank"}), 400
        
    # Extract features
    features_dict = extract_features(url)
    features_list = get_feature_list(url)
    
    prediction_label = "Safe"
    confidence_val = 100.0
    
    # Run ML prediction if loaded, else use heuristic fallback
    if phishing_model is not None:
        try:
            # Predict
            pred = phishing_model.predict([features_list])[0] # 0 = safe, 1 = phishing
            prediction_label = "Phishing" if pred == 1 else "Safe"
            
            # Confidence calculation
            probas = phishing_model.predict_proba([features_list])[0]
            confidence_val = max(probas) * 100.0
        except Exception as e:
            print(f"ML Scan prediction failed: {e}. Falling back to heuristics.")
            # Heuristic fallback prediction
            h_score = calculate_heuristic_risk(url, features_dict)
            prediction_label = "Phishing" if h_score >= 50 else "Safe"
            confidence_val = float(h_score) if prediction_label == "Phishing" else float(100 - h_score)
    else:
        # Static heuristic detection logic
        h_score = calculate_heuristic_risk(url, features_dict)
        prediction_label = "Phishing" if h_score >= 50 else "Safe"
        confidence_val = float(h_score) if prediction_label == "Phishing" else float(100 - h_score)

    risk_score = calculate_heuristic_risk(url, features_dict)
    
    # User ID association if logged in
    user_id = session.get('user_id')
    
    # Build Scan History model
    scan_record = ScanHistory(
        user_id=user_id,
        url=url,
        prediction=prediction_label,
        confidence_score=confidence_val,
        risk_score=risk_score,
        features=json.dumps(features_dict)
    )
    
    db.session.add(scan_record)
    db.session.commit()
    
    # Prepare API payload response
    result_payload = {
        "id": scan_record.id,
        "url": scan_record.url,
        "prediction": scan_record.prediction,
        "confidence_score": scan_record.confidence_score,
        "risk_score": scan_record.risk_score,
        "features": features_dict,
        "created_at": scan_record.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return jsonify({"success": True, "result": result_payload})


# --- PDF Generating / Download Route ---

@app.route('/report/<int:scan_id>')
@login_required
def download_report(scan_id):
    scan_record = ScanHistory.query.filter_by(id=scan_id).first()
    
    if not scan_record:
        flash('Audit scan record not found.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Check authorization (Users can only access their own reports, Admins can access all)
    if scan_record.user_id != session.get('user_id') and session.get('role') != 'admin':
        flash('Access unauthorized to requested report.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Generate PDF
    user_obj = db.session.get(User, scan_record.user_id) if scan_record.user_id else None
    username_str = user_obj.username if user_obj else "Anonymous"
    
    pdf_bytes = generate_scan_pdf(scan_record, username_str)
    
    # Return response stream
    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    filename = f"CyberShield_Report_Scan_{scan_id}.pdf"
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response


# --- User Dashboard Route ---

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    
    # Query user metrics
    scans_count = ScanHistory.query.filter_by(user_id=user_id).count()
    safe_count = ScanHistory.query.filter_by(user_id=user_id, prediction='Safe').count()
    phish_count = ScanHistory.query.filter_by(user_id=user_id, prediction='Phishing').count()
    
    scans = ScanHistory.query.filter_by(user_id=user_id).order_by(ScanHistory.created_at.desc()).all()
    quiz_results = QuizResult.query.filter_by(user_id=user_id).order_by(QuizResult.completed_at.desc()).all()
    
    return render_template(
        'dashboard.html',
        scans_count=scans_count,
        safe_count=safe_count,
        phish_count=phish_count,
        scans=scans,
        quiz_results=quiz_results
    )


# --- Cybersecurity Toolkit & API Routes ---

@app.route('/toolkit')
@login_required
def toolkit():
    user_id = session.get('user_id')
    # Fetch recent scans for the logged in user
    scans = ScanHistory.query.filter_by(user_id=user_id).order_by(ScanHistory.created_at.desc()).limit(10).all()
    return render_template('toolkit.html', scans=scans)


@app.route('/api/log-password-check', methods=['POST'])
@login_required
def log_password_check():
    data = request.get_json() or {}
    score = data.get('score')
    strength = data.get('strength')
    
    if score is None or not strength:
        return jsonify({"success": False, "error": "Invalid request parameters"}), 400
        
    user_id = session.get('user_id')
    
    check_record = PasswordStrengthCheck(
        user_id=user_id,
        score=score,
        strength=strength
    )
    db.session.add(check_record)
    db.session.commit()
    
    return jsonify({"success": True})


@app.route('/api/log-password-generation', methods=['POST'])
@login_required
def log_password_generation():
    data = request.get_json() or {}
    length = data.get('length')
    entropy = data.get('entropy')
    
    if length is None or entropy is None:
        return jsonify({"success": False, "error": "Invalid request parameters"}), 400
        
    user_id = session.get('user_id')
    
    gen_record = PasswordGenerated(
        user_id=user_id,
        length=length,
        entropy=entropy
    )
    db.session.add(gen_record)
    db.session.commit()
    
    return jsonify({"success": True})


@app.route('/api/dashboard-analytics')
@login_required
def dashboard_analytics():
    user_id = session.get('user_id')
    
    # 1. URL metrics
    all_scans = ScanHistory.query.filter_by(user_id=user_id).all()
    total_scans = len(all_scans)
    safe_scans = sum(1 for s in all_scans if s.prediction == 'Safe' and s.risk_score <= 30)
    suspicious_scans = sum(1 for s in all_scans if s.prediction == 'Safe' and s.risk_score > 30)
    phishing_scans = sum(1 for s in all_scans if s.prediction == 'Phishing')
    
    # 2. Password metrics
    all_checks = PasswordStrengthCheck.query.filter_by(user_id=user_id).all()
    avg_password_strength = 0
    if all_checks:
        avg_password_strength = int(sum(c.score for c in all_checks) / len(all_checks))
        
    total_passwords_generated = PasswordGenerated.query.filter_by(user_id=user_id).count()
    
    # 3. Trends
    scans_sorted = sorted(all_scans, key=lambda x: x.created_at)
    scans_for_trend = scans_sorted[-8:]
    scan_risk_scores = [s.risk_score for s in scans_for_trend]
    scan_dates = [s.created_at.strftime('%m-%d') for s in scans_for_trend]
    
    checks_sorted = sorted(all_checks, key=lambda x: x.created_at)
    checks_for_trend = checks_sorted[-8:]
    password_strength_scores = [c.score for c in checks_for_trend]
    password_dates = [c.created_at.strftime('%m-%d') for c in checks_for_trend]
    
    # Defaults if no data
    if not scan_risk_scores:
        scan_risk_scores = [5, 85, 10, 95, 65, 98]
        scan_dates = ["5d ago", "4d ago", "3d ago", "2d ago", "1d ago", "Today"]
        
    if not password_strength_scores:
        password_strength_scores = [40, 60, 85, 90]
        password_dates = ["4d ago", "3d ago", "2d ago", "Today"]
        
    # Activity heatmap data (frequency of action by Day of Week 0-6 and hour block 0-3)
    heatmap_data = {
        "days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "hours": ["00-06", "06-12", "12-18", "18-00"],
        "matrix": [[0]*4 for _ in range(7)]
    }
    
    def add_to_heatmap(dt):
        day = dt.weekday()
        hour_block = dt.hour // 6
        heatmap_data["matrix"][day][hour_block] += 1
        
    for s in all_scans:
        add_to_heatmap(s.created_at)
    for c in all_checks:
        add_to_heatmap(c.created_at)
    for q in QuizResult.query.filter_by(user_id=user_id).all():
        add_to_heatmap(q.completed_at)
        
    # Seed heatmap matrix with some values if it is completely empty
    total_heatmap_points = sum(sum(row) for row in heatmap_data["matrix"])
    if total_heatmap_points == 0:
        heatmap_data["matrix"] = [
            [2, 5, 4, 1], # Mon
            [1, 6, 2, 3], # Tue
            [4, 8, 3, 2], # Wed
            [3, 5, 6, 1], # Thu
            [5, 4, 9, 3], # Fri
            [1, 2, 3, 4], # Sat
            [2, 1, 2, 1]  # Sun
        ]
        
    return jsonify({
        "success": True,
        "url_analytics": {
            "total": total_scans,
            "safe": safe_scans,
            "suspicious": suspicious_scans,
            "phishing": phishing_scans
        },
        "password_analytics": {
            "average_strength_score": avg_password_strength,
            "total_generated": total_passwords_generated
        },
        "trends": {
            "scan_risk_scores": scan_risk_scores,
            "scan_dates": scan_dates,
            "password_strength_scores": password_strength_scores,
            "password_dates": password_dates
        },
        "heatmap": heatmap_data
    })


# --- Awareness Quiz Save Result Route ---

@app.route('/quiz')
@login_required
def quiz():
    return render_template('quiz.html')

@app.route('/save-quiz', methods=['POST'])
@login_required
def save_quiz():
    data = request.get_json() or {}
    score = data.get('score')
    total = data.get('total')
    
    if score is None or total is None:
        return jsonify({"success": False, "error": "Invalid scores passed"}), 400
        
    user_id = session.get('user_id')
    
    # Generate verification certificate identifier
    cert_uid = f"CERT-{datetime.utcnow().year}-{uuid.uuid4().hex[:6].upper()}"
    
    quiz_record = QuizResult(
        user_id=user_id,
        score=score,
        total_questions=total,
        certificate_code=cert_uid
    )
    
    db.session.add(quiz_record)
    db.session.commit()
    
    return jsonify({
        "success": True, 
        "certificate_code": cert_uid
    })

@app.route('/certificate/<string:code>')
@login_required
def certificate(code):
    result = QuizResult.query.filter_by(certificate_code=code).first()
    if not result:
        flash('Requested certificate credential code not found.', 'danger')
        return redirect(url_for('dashboard'))
        
    user = db.session.get(User, result.user_id)
    
    # Validate access
    if result.user_id != session.get('user_id') and session.get('role') != 'admin':
        flash('Unauthorized access to printable certificate.', 'danger')
        return redirect(url_for('dashboard'))
        
    return render_template('certificate.html', result=result, user=user)


# --- Administrative Panels ---

@app.route('/admin')
@admin_required
def admin_dashboard():
    # Counts
    total_users = User.query.count()
    total_scans = ScanHistory.query.count()
    total_safe = ScanHistory.query.filter_by(prediction='Safe').count()
    total_phish = ScanHistory.query.filter_by(prediction='Phishing').count()
    
    # Detailed entities lists
    users_list = User.query.all()
    scan_history = ScanHistory.query.order_by(ScanHistory.created_at.desc()).all()
    admin_logs = AdminLog.query.order_by(AdminLog.created_at.desc()).all()
    
    return render_template(
        'admin.html',
        total_users=total_users,
        total_scans=total_scans,
        total_safe=total_safe,
        total_phish=total_phish,
        users_list=users_list,
        scan_history=scan_history,
        admin_logs=admin_logs
    )

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('Operation blocked: Admin cannot delete their own active account.', 'danger')
        return redirect(url_for('admin_dashboard'))
        
    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        flash('User account not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
        
    username_placeholder = user_to_delete.username
    
    # Log deletion before actual deletion
    log_item = AdminLog(
        admin_id=session.get('user_id'),
        action=f"Deleted user account '{username_placeholder}' (ID: {user_id}).",
        target_user_id=None,
        ip_address=request.remote_addr
    )
    db.session.add(log_item)
    
    db.session.delete(user_to_delete)
    db.session.commit()
    
    flash(f"User account '{username_placeholder}' and all associated records deleted.", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/export/scans')
@admin_required
def admin_export_scans():
    scans = ScanHistory.query.order_by(ScanHistory.created_at.desc()).all()
    
    # Generate CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Scan_ID', 'User_ID', 'URL_Address', 'Prediction_Verdict', 
        'ML_Confidence_Score', 'Heuristic_Risk_Score', 'Timestamp'
    ])
    
    for s in scans:
        writer.writerow([
            s.id,
            s.user_id if s.user_id else 'Anonymous',
            s.url,
            s.prediction,
            f"{s.confidence_score:.2f}%",
            f"{s.risk_score}/100",
            s.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
        
    # Log exporting action
    log_item = AdminLog(
        admin_id=session.get('user_id'),
        action="Exported system scan report data ledger to CSV format.",
        target_user_id=None,
        ip_address=request.remote_addr
    )
    db.session.add(log_item)
    db.session.commit()
    
    # Prepare Flask response headers
    response = make_response(output.getvalue())
    response.headers['Content-type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=PhishGuard_System_Scans_{datetime.utcnow().strftime("%Y-%m-%d")}.csv'
    return response


# --- Security Headers ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data: https://images.unsplash.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# --- Custom Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    logging.warning(f"404 Error: {request.url} - {request.remote_addr}")
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f"500 Error: {e} - {request.url} - {request.remote_addr}")
    return render_template('errors/500.html'), 500


if __name__ == '__main__':
    # Run server locally on default development port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)