# POWERPOINT PRESENTATION OUTLINE
## PROJECT: AI-Powered Phishing Detection & Awareness Platform
**Audience:** B.Tech IT Capstone Project Jury / Evaluators  
**Total Slides:** 19 Slides  

---

### SLIDE 1: Title & Project Team
- **Slide Title:** AI-Powered Phishing Detection & Awareness Platform
- **Subtitle:** A B.Tech Capstone Project in Information Technology
- **Contents:**
  - **Presented By:** B.Tech IT Project Team
  - **Academic Session:** 2025 - 2026
  - **Technologies:** Python Flask, Scikit-Learn (Random Forest), MySQL, Bootstrap 5, ReportLab
- **Presenter Notes:** Good morning members of the jury. Today we present our final-year project, PhishGuard, a unified cybersecurity platform combining AI-driven web-link classification with interactive user education.

---

### SLIDE 2: Project Overview
- **Slide Title:** Project Overview
- **Bullet Points:**
  - **Unified Security Checkpoint:** An active URL scanning interface for users and admins.
  - **Predictive AI Classification:** Bypasses traditional signature constraints to analyze link structures in real-time.
  - **Awareness LMS:** Tackles the "human element" of cybersecurity through educational guides and quizzes.
  - **Administrative Audit Logs:** Monitors user activity, scan ledger reports, and database statistics.

---

### SLIDE 3: Problem Statement
- **Slide Title:** The Phishing Threat Landscape
- **Bullet Points:**
  - **Primary Entry Vector:** Over 85% of corporate cyber breaches start with phishing emails.
  - **Ephemeral Domains:** Phishing sites remain active for an average of 4-6 hours, making static blacklists (e.g., Google Safe Browsing) reactive.
  - **Zero-Day Attacks:** Cybercriminals modify subdomains and redirection chains to target credentials before systems detect them.
  - **The Human Factor:** Technology alone cannot prevent security breaches if users lack cybersecurity training.

---

### SLIDE 4: Project Objectives
- **Slide Title:** Project Aims & Scope
- **Bullet Points:**
  - Build a dynamic feature extractor to parse URLs and detect structural threats.
  - Train an ensemble Machine Learning model (Random Forest) to achieve classification accuracy > 95%.
  - Implement a secure Python Flask backend with Session Authentication and Role-Based Access Control (RBAC).
  - Design a database to record scans, quiz scores, and admin audit logs.
  - Develop an interactive quiz system with automated certificate generation and printable PDF scan reports.

---

### SLIDE 5: System Architecture
- **Slide Title:** High-Level System Architecture
- **Contents:**
  - **Visual Layers Diagram:**
    - *Client Layer:* Web Browser executing HTML5, CSS Variables, Bootstrap 5, Vanilla JS, and Chart.js.
    - *Controller Layer:* Flask Web Application Server, custom URL Feature Extractor, loaded Random Forest PKL model, and ReportLab PDF Compiler.
    - *Database Layer:* MySQL relational schema tracking user profiles, scans, and system logs.

---

### SLIDE 6: Database Schema & Entity Relations
- **Slide Title:** Relational Database Design
- **Bullet Points:**
  - **`users` Table:** Tracks User IDs, emails, roles (Admin/User), and hashed passwords (via Scrypt).
  - **`scan_history` Table:** Stores url queries, prediction output, confidence score, threat index and extracted features.
  - **`quiz_results` Table:** Records user quiz scores and certificate verification codes.
  - **`admin_logs` Table:** Logs administrative actions (e.g., user deletions, data exports) with IP addresses for auditing.

---

### SLIDE 7: URL Feature Engineering
- **Slide Title:** URL Feature Engineering
- **Bullet Points:**
  - **Structural Features:** URL length, subdomain counts, hyphens in domain, and double slash redirection (`//`).
  - **Security Features:** SSL Final State (HTTP vs HTTPS).
  - **Semantic Features:** Count of suspicious keywords (e.g., `login`, `secure`, `verify`, `bank`).
  - **Anomalous Features:** Presence of the `@` symbol (ignores preceding text) and IP-based hostnames.

---

### SLIDE 8: Machine Learning Engine
- **Slide Title:** The Random Forest Classifier
- **Bullet Points:**
  - **Ensemble Method:** Uses a forest of 100 decision trees to classify URLs.
  - **Bagging & Random Subsets:** Reduces variance and prevents overfitting, making it robust against noisy inputs.
  - **Majority Voting:** Each tree votes (Safe vs Phishing); the majority class determines the final prediction.
  - **Class Probabilities:** Evaluates voting ratios to calculate a statistical confidence score.

---

### SLIDE 9: Model Performance Results
- **Slide Title:** Model Evaluation Metrics
- **Table / Data:**
  - **Validation Accuracy:** 98.63%
  - **Confusion Matrix:** True Negatives: 101 | False Positives: 0 | False Negatives: 3 | True Positives: 115
  - **Precision:** Safe: 97.12% | Phishing: 100.00%
  - **Recall:** Safe: 100.00% | Phishing: 97.46%
- **Presenter Notes:** The model achieved 98.63% accuracy. It successfully identified 100% of benign sites and misclassified only 3 phishing URLs, indicating high reliability.

---

### SLIDE 10: Feature Importance Breakdown
- **Slide Title:** What Makes a URL Suspicious?
- **Bullet Points (Sorted by weight):**
  - **SSL Scheme final state (HTTP vs HTTPS):** 50.27% (Primary indicator)
  - **Suspicious keywords count:** 21.68%
  - **Prefix-Suffix (hyphens in domain):** 14.95%
  - **Subdomain count:** 7.07%
  - **IP Address usage:** 4.34%
  - **URL Length & Special Characters:** Remaining weight

---

### SLIDE 11: Backend Control & API Design
- **Slide Title:** Flask Controller Implementation
- **Bullet Points:**
  - **Secure Auth Pipeline:** Uses Werkzeug's `generate_password_hash` and `check_password_hash` to store credentials securely.
  - **REST API Endpoint (`/scan`):** Handles URL scanning requests asynchronously.
  - **RBAC Filters:** Restricts access to administrator portals using custom decorators.
  - **Database Integration:** Utilizes SQLAlchemy ORM to prevent SQL Injection.

---

### SLIDE 12: PDF Report Compiler
- **Slide Title:** Automated PDF Report Engine
- **Bullet Points:**
  - Developed using the **ReportLab Platypus** framework.
  - Compiles URL metadata, verdicts, confidence levels, and heuristic checks into an audit document.
  - Automatically wraps long URL strings to fit standard page layouts.
  - Generates downloadable reports for user reference.

---

### SLIDE 13: Frontend Design & Themes
- **Slide Title:** UI/UX & Theme Personalization
- **Bullet Points:**
  - Built with **Bootstrap 5** and custom CSS stylesheets.
  - Uses CSS custom properties to enable responsive styling across devices.
  - Features **Dark Mode** support, with theme preferences saved locally (`localStorage`) for persistence.
  - Displays real-time scan statistics using interactive charts (**Chart.js**).

---

### SLIDE 14: Cybersecurity Learning Center
- **Slide Title:** Cybersecurity Awareness Hub
- **Bullet Points:**
  - Hosts educational security articles covering phishing tactics and prevention.
  - Features simulated email templates (e.g., account suspensions, corporate IT notifications) to help users identify red flags.
  - Promotes best practices like enabling Multi-Factor Authentication (MFA) and using password managers.

---

### SLIDE 15: Interactive Quiz & Certification
- **Slide Title:** Quiz & Automated Certification
- **Bullet Points:**
  - Includes a 10-question MCQ quiz focused on identifying phishing vectors.
  - Displays explanations after each submission.
  - Automatically awards a **Security Champion Certificate** to users scoring 8/10 or higher.
  - Certificates are saved to the user dashboard and are printable.

---

### SLIDE 16: Administrative Audit Engine
- **Slide Title:** Administrator Oversight Portal
- **Bullet Points:**
  - Provides a dashboard showing registered users and system-wide scan statistics.
  - Allows admins to delete user accounts and their associated records.
  - Tracks admin activities (e.g., logins, data exports) in the `admin_logs` table for auditing.
  - Supports exporting all scan logs to a CSV file for compliance reporting.

---

### SLIDE 17: Project Limitations
- **Slide Title:** System Limitations
- **Bullet Points:**
  - **URL-Only Analysis:** The system evaluates URL structures and does not scan the active webpage content. Phishing pages hosted on compromised legitimate domains may bypass detection.
  - **Heuristics Overrides:** Obfuscated redirection paths require continuous heuristic updates.
  - **External Whitelists:** The scanner operates independently without querying third-party domain databases.

---

### SLIDE 18: Future Work
- **Slide Title:** Future Scope & Extensions
- **Bullet Points:**
  - **Dynamic Page Scraping:** Integrate BeautifulSoup to analyze webpage forms and link distributions.
  - **Browser Extension:** Package the feature extractor into a Chrome extension for real-time protection.
  - **Active Crawler Security:** Set up sandbox crawlers to detect active redirect scripts and malicious payloads.

---

### SLIDE 19: Q&A / Conclusion
- **Slide Title:** Conclusion & Questions
- **Bullet Points:**
  - Successfully built a complete, production-ready phishing detection web application.
  - Validated the Random Forest Classifier with an accuracy of **98.63%**.
  - Integrated technological security with educational resources to address the human element of cyber threats.
- **Presenter Notes:** Thank you for your time. We are now open for any questions and feedback from the jury.
