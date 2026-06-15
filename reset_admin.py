"""
Admin Password Reset Script
Usage: python reset_admin.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, hash_password
from models import User

NEW_PASSWORD = "Admin@123"   # <-- Change this to your desired password

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if admin:
        admin.password_hash = hash_password(NEW_PASSWORD)
        db.session.commit()
        print(f"[OK] Admin password reset successfully!")
        print(f"   Username : admin")
        print(f"   Password : {NEW_PASSWORD}")
        print(f"   Login at : http://127.0.0.1:5000/login")
    else:
        print("[ERROR] Admin user not found!")
