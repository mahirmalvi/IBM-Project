import os
from datetime import datetime, timedelta
import bcrypt

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
from sqlalchemy import text

def init_db(app, db):
    """
    Initializes the database by creating tables and seeding default mock data 
    if the database is empty.
    """
    with app.app_context():
        # Import models inside context to avoid circular import issues
        from models import User, ScanHistory, QuizResult, AdminLog, PasswordStrengthCheck, PasswordGenerated
        
        print("Creating database tables if they do not exist...")
        db.create_all()
        
        # Check if users already exist
        if User.query.first() is not None:
            print("Database already contains data. Skipping seeding.")
            return
            
        print("Seeding database with default user accounts...")
        
        # 1. Create Default Admin
        admin_user = User(
            username="admin",
            email="admin@phishguard.org",
            password_hash=hash_password("admin123"),
            role="admin"
        )
        db.session.add(admin_user)
        
        # 2. Create Default Standard User
        demo_user = User(
            username="user",
            email="user@phishguard.org",
            password_hash=hash_password("user123"),
            role="user"
        )
        db.session.add(demo_user)
        
        # Commit users first so they get IDs (1 and 2)
        db.session.commit()
        print(f"Created accounts: Admin (ID: {admin_user.id}) and Demo User (ID: {demo_user.id}).")
        
        # 3. Seed Scan History
        print("Seeding mock scan records...")
        now = datetime.utcnow()
        scans = [
            ScanHistory(
                user_id=demo_user.id,
                url="https://www.google.com",
                prediction="Safe",
                confidence_score=98.7,
                risk_score=5,
                features='{"url_length": 22, "having_ip_address": 0, "shortening_service": 0, "having_at_symbol": 0, "double_slash_redirecting": 0, "prefix_suffix": 0, "having_sub_domain": 0, "ssl_final_state": 1, "suspicious_keywords": 0}',
                created_at=now - timedelta(days=5)
            ),
            ScanHistory(
                user_id=demo_user.id,
                url="http://paypal-security-login.com/webapps/home",
                prediction="Phishing",
                confidence_score=91.2,
                risk_score=85,
                features='{"url_length": 45, "having_ip_address": 0, "shortening_service": 0, "having_at_symbol": 0, "double_slash_redirecting": 0, "prefix_suffix": 1, "having_sub_domain": 1, "ssl_final_state": 0, "suspicious_keywords": 2}',
                created_at=now - timedelta(days=4)
            ),
            ScanHistory(
                user_id=demo_user.id,
                url="https://github.com/login",
                prediction="Safe",
                confidence_score=95.4,
                risk_score=10,
                features='{"url_length": 24, "having_ip_address": 0, "shortening_service": 0, "having_at_symbol": 0, "double_slash_redirecting": 0, "prefix_suffix": 0, "having_sub_domain": 0, "ssl_final_state": 1, "suspicious_keywords": 1}',
                created_at=now - timedelta(days=3)
            ),
            ScanHistory(
                user_id=demo_user.id,
                url="http://192.168.1.100/secure/bankofamerica/login.html",
                prediction="Phishing",
                confidence_score=96.8,
                risk_score=95,
                features='{"url_length": 53, "having_ip_address": 1, "shortening_service": 0, "having_at_symbol": 0, "double_slash_redirecting": 0, "prefix_suffix": 0, "having_sub_domain": 0, "ssl_final_state": 0, "suspicious_keywords": 3}',
                created_at=now - timedelta(days=2)
            ),
            ScanHistory(
                user_id=demo_user.id,
                url="https://bit.ly/3xY7zhD",
                prediction="Phishing",
                confidence_score=74.3,
                risk_score=65,
                features='{"url_length": 21, "having_ip_address": 0, "shortening_service": 1, "having_at_symbol": 0, "double_slash_redirecting": 0, "prefix_suffix": 0, "having_sub_domain": 0, "ssl_final_state": 1, "suspicious_keywords": 0}',
                created_at=now - timedelta(days=1)
            ),
            ScanHistory(
                user_id=demo_user.id,
                url="https://amazon.update-account-security-verification.com/login",
                prediction="Phishing",
                confidence_score=98.1,
                risk_score=98,
                features='{"url_length": 62, "having_ip_address": 0, "shortening_service": 0, "having_at_symbol": 0, "double_slash_redirecting": 0, "prefix_suffix": 1, "having_sub_domain": 1, "ssl_final_state": 1, "suspicious_keywords": 3}',
                created_at=now
            )
        ]
        db.session.add_all(scans)
        
        # 4. Seed Quiz Results
        print("Seeding quiz progress...")
        quizzes = [
            QuizResult(
                user_id=demo_user.id,
                score=8,
                total_questions=10,
                completed_at=now - timedelta(days=3),
                certificate_code="CERT-2026-6FE721"
            ),
            QuizResult(
                user_id=demo_user.id,
                score=10,
                total_questions=10,
                completed_at=now - timedelta(days=1),
                certificate_code="CERT-2026-9AA410"
            )
        ]
        db.session.add_all(quizzes)
        
        # 5. Seed Admin Audit Logs
        print("Seeding admin audit logs...")
        logs = [
            AdminLog(
                admin_id=admin_user.id,
                action="System Initialized",
                target_user_id=None,
                ip_address="127.0.0.1",
                created_at=now - timedelta(days=6)
            ),
            AdminLog(
                admin_id=admin_user.id,
                action="Registered default admin account",
                target_user_id=admin_user.id,
                ip_address="127.0.0.1",
                created_at=now - timedelta(days=6)
            ),
            AdminLog(
                admin_id=admin_user.id,
                action="Registered default demo user account",
                target_user_id=demo_user.id,
                ip_address="127.0.0.1",
                created_at=now - timedelta(days=5)
            ),
            AdminLog(
                admin_id=admin_user.id,
                action="Exported system scan report to CSV",
                target_user_id=None,
                ip_address="192.168.1.15",
                created_at=now - timedelta(days=2)
            )
        ]
        db.session.add_all(logs)
        
        db.session.commit()
        print("Database seeding completed successfully.")
