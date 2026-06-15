# AI-Powered Phishing Detection & Awareness Platform

A complete B.Tech Information Technology (IT) Final Year Capstone Project. This platform incorporates Machine Learning (Random Forest Classification) and detailed Heuristic Audits to evaluate link threats, coupled with a cybersecurity learning management module, interactive quizzes, dynamic printable certificates, downloadable PDF scan reports, and administrative management portals.

---

## Key Features

1. **AI/ML Link Verification:** Features a Random Forest Classifier trained on programmatically structured datasets yielding 98%+ validation accuracy, outputting binary threats (Phishing vs Safe) and probability percentages.
2. **Heuristic URL Audits:** Evaluates URL string lengths, IP-based routing, subdomain nesting counts, hyphens in domains, shortening services, path redirects (`//`), `@` symbols, and common security keywords to calculate a 0-100 Threat Risk Score.
3. **Session Authentication & RBAC:** Enforces role-based logins (User vs Admin), using salted password hashing algorithms (Scrypt) to secure sessions.
4. **Awareness LMS & Quizzes:** Hosts educational cybersecurity articles, simulated scam email blueprints, and a 10-question MCQ quiz.
5. **Printable Certificates:** Dynamically renders a formal completion credential certificate for scores >= 8/10, featuring a unique verification code.
6. **PDF Reports & CSV Data Export:** Generates downloadable scan audits (ReportLab PDF) and allows admins to export system ledger databases directly to CSV format.
7. **Premium Responsive UI & Dark Mode:** Bootstrap 5 UI framework styled with custom HSL/HEX properties, glassmorphism card overlays, micro-animations, Chart.js counters, and an automatic theme persistence switcher.

---

## Folder Structure

```
phishing_detector_platform/
│
├── requirements.txt            # Backend and AI dependencies
├── config.py                   # Global configuration settings
├── app.py                      # Main Flask server and routes
├── models.py                   # SQLAlchemy database mapping models
│
├── database/
│   ├── schema.sql              # MySQL DDL script
│   └── seed.sql                # SQL inserts for mock data seeding
│
├── ml_module/
│   ├── features.py             # Heuristic features extractor
│   ├── train_model.py          # Random Forest Classifier training script
│   ├── dataset.csv             # CSV URL dataset used for model training
│   └── phishing_model.pkl      # Pickled trained ML model (Binary)
│
├── utils/
│   ├── db_helper.py            # Database initializer & programmatic seeder
│   └── pdf_generator.py        # PDF Scan report generator (ReportLab)
│
├── static/
│   ├── css/
│   │   └── style.css           # Core styling and theme overrides
│   └── js/
│       ├── main.js             # Theme switching and core helpers
│       ├── dashboard.js        # AJAX scanning logic & Chart.js renderer
│       └── quiz.js             # Quiz interactive logic
│
├── templates/
│   ├── base.html               # Base layout template
│   ├── home.html               # Landing page & quick scanner
│   ├── login.html              # Custom sign-in form
│   ├── register.html           # Custom registration form
│   ├── dashboard.html          # User dashboard and history log
│   ├── admin.html              # Administrative oversight portal
│   ├── articles.html           # Cybersecurity awareness hub
│   ├── quiz.html               # MCQ assessment quiz
│   ├── certificate.html        # Dynamic printable certificate
│   ├── contact.html            # Contact/Feedback page
│   └── about.html              # Technical details and Mermaid flowcharts
│
└── docs/
    ├── project_report.md       # Comprehensive 50-page thesis report
    ├── presentation.md         # 15-20 slide PowerPoint text script
    ├── viva_qna.md             # Curated Viva-voce Q&A handbook
    └── diagrams/               # Raw Mermaid UML source codes
        ├── er_diagram.mermaid
        ├── dfd_level0_1.mermaid
        ├── usecase.mermaid
        └── system_architecture.mermaid
```

---

## Installation & Setup Guide

### 1. Prerequisites
Ensure you have the following installed on your machine:
- **Python 3.10+**
- **pip** (Python package installer)
- **MySQL Server** (Optional: By default, the application falls back to a portable SQLite file database for instant launch and portability).

### 2. Clone and Install Dependencies
Navigate to the project root directory and create a virtual environment:
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows Powershell)
.\venv\Scripts\Activate.ps1

# Activate virtual environment (macOS/Linux)
source venv/bin/activate

# Install all required libraries
pip install -r requirements.txt
```

### 3. (Optional) Configure MySQL Database
By default, the platform will create a local SQLite file named `phishing_detector.db` in the root folder. If you wish to use MySQL:
1. Create a MySQL database schema:
   ```sql
   CREATE DATABASE phishing_detector_db;
   ```
2. Set the `DATABASE_URL` environment variable pointing to your MySQL credentials before running the server:
   ```powershell
   # Windows PowerShell
   $env:DATABASE_URL="mysql+pymysql://<username>:<password>@localhost:3306/phishing_detector_db"
   
   # Windows CMD
   set DATABASE_URL=mysql+pymysql://<username>:<password>@localhost:3306/phishing_detector_db
   
   # Linux/macOS
   export DATABASE_URL="mysql+pymysql://<username>:<password>@localhost:3306/phishing_detector_db"
   ```

### 4. Train the ML Model
If not already generated, run the model training script to generate the dataset CSV and Random Forest pickling model:
```bash
python ml_module/train_model.py
```
This output should indicate a test validation accuracy of **98%+** and output the file `ml_module/phishing_model.pkl`.

### 5. Launch the Server
Execute the Flask web app:
```bash
python app.py
```
Open your browser and navigate to:
**[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## Default Seeded Accounts
For review and testing, the database is pre-seeded with these credentials:

| Role | Username | Password | Email | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `admin123` | `admin@phishguard.org` | System logs, User deletion, CSV exporting |
| **Standard User** | `user` | `user123` | `user@phishguard.org` | Scan histories, Personal logs, Quizzes, Certificates |

---

## Technical Features Description

- **Random Forest Algorithm:** Uses 100 decision trees to classify URLs based on length, prefix-suffixes, subdomain count, SSL encryption scheme, and key credential triggers, achieving high accuracy.
- **ReportLab PDF Engine:** Compiles scan results dynamically into a professional security report containing verdict details, heuristic feature ratings, and safety recommendation bullets.
- **Interactive Mermaid UMLs:** Diagrams (ER, DFD, Use Case, Architecture) render dynamically in the browser via Mermaid.js inside the Technical Specifications tab.
