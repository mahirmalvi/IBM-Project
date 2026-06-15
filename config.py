import os

class Config:
    # Secret key for signing sessions and cookies
    SECRET_KEY = os.environ.get('SECRET_KEY', 'phishguard_secure_jwt_session_secret_998822')
    
    # Security Configuration
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    
    # Database Configuration:
    # To use MySQL: Set the DATABASE_URL environment variable to:
    # mysql+pymysql://<username>:<password>@<host>:<port>/<database_name>
    # Example: mysql+pymysql://root:rootpassword@localhost:3306/phishing_detector_db
    # By default, it falls back to a portable local SQLite database file.
    
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phishing_detector.db')
    )
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Upload folder for report generation or media (if any)
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
    
    # Ensure upload folder exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
