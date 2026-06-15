# PROJECT REPORT
## TITLE: AI-Powered Phishing Detection & Awareness Platform
**Academic Session:** 2025 - 2026  
**Degree:** Bachelor of Technology (B.Tech) in Information Technology  

---

## ABSTRACT

Phishing remains one of the most persistent and devastating vectors for cyber attacks, acting as the primary entry point for credential theft, ransomware, and corporate data breaches. Modern phishing URLs are highly ephemeral, bypassing traditional signature-based security filters and blacklists. This project presents the design, development, and evaluation of **PhishGuard**, an **AI-Powered Phishing Detection & Awareness Platform** that combines real-time Machine Learning (ML) classification with static heuristic analysis to assess link safety.

The classification engine is built upon a **Random Forest Classifier** composed of 100 decision trees. It processes URLs by dynamically extracting 9 structural, semantic, and security features: URL length, presence of IP address, URL shortening patterns, the `@` redirection symbol, double slash (`//`) path anomalies, hyphens in the domain, subdomain nesting levels, SSL final state (HTTP vs HTTPS), and brand keyword occurrences. The ML model is integrated into a lightweight, secure **Python Flask** backend framework supporting Session Authentication, Role-Based Access Control (RBAC), and relational tracking via a **MySQL/SQLite** persistence layer.

To combat the human element of security breaches, the platform hosts an **Awareness Module** comprising simulated phishing templates, structured learning guides, and an interactive MCQ assessment quiz. Users who demonstrate proficiency by scoring 80% or higher are awarded a unique, printable **Phishing Awareness Security Champion Certificate**. Furthermore, the platform supports administrative operations (user directory management, audit logs tracking, CSV exports) and dynamic PDF analysis report compilation. Validation results show that the Random Forest model achieves an classification accuracy of **98.63%**, establishing the platform as a robust, scalable security auditing and training solution.

---

## TABLE OF CONTENTS
1. **Chapter 1: Introduction**
   - 1.1 Problem Statement & Background
   - 1.2 Aims and Objectives
   - 1.3 Scope of the Capstone Project
2. **Chapter 2: Literature Survey**
   - 2.1 Existing Phishing Detection Approaches
   - 2.2 Critique of Blacklist-based Methods
   - 2.3 Machine Learning Algorithms Comparison
3. **Chapter 3: System Requirements Analysis**
   - 3.1 Functional Requirements
   - 3.2 Non-Functional Requirements
   - 3.3 Hardware and Software Specifications
4. **Chapter 4: Methodology & System Design**
   - 4.1 High-Level Architecture
   - 4.2 URL Feature Engineering & Extraction
   - 4.3 Random Forest Mathematical Foundation
   - 4.4 Relational Database Schema Design
5. **Chapter 5: System Implementation**
   - 5.1 Model Training & Serializing Workflow
   - 5.2 Flask Routing & Controller APIs
   - 5.3 PDF Report Compilation Engine
   - 5.4 Frontend Aesthetic Layouts and Dark Mode
6. **Chapter 6: System Testing & Evaluation**
   - 6.1 Model Performance Analytics
   - 6.2 Unit and Integration Testing
   - 6.3 Admin Audit Logging and Data Export
7. **Chapter 7: Awareness & Training LMS**
   - 7.1 Learning Curriculums and Phishing Blueprints
   - 7.2 Quiz Evaluation & Automated Certificate Generation
8. **Chapter 8: Conclusion & Future Scope**
   - 8.1 Critical Summary of Accomplishments
   - 8.2 Project Limitations
   - 8.3 Future Enhancements
9. **References**

---

## CHAPTER 1: INTRODUCTION

### 1.1 Problem Statement & Background
In the current era of ubiquitous cloud infrastructure and distributed work environments, digital communication forms the backbone of commercial and personal transactions. However, this relies on trust, which is routinely exploited by malicious actors. Phishing—the act of crafting deceptive electronic communications to trick individuals into revealing sensitive credentials, financial data, or executing unauthorized payloads—remains the leading cyber threat vector globally. 

According to global security bulletins, over 85% of corporate cyber breaches start with social engineering, primarily via deceptive links. Traditional security systems rely on **blacklists** (e.g., Google Safe Browsing, PhishTank) that maintain databases of reported malicious URLs. While effective for known threats, blacklists fail completely when encountering **zero-day phishing sites**. Attackers evade detection by registering highly disposable domains, utilizing URL shorteners, and keeping the phishing page active for only a few hours. There is a critical requirement for a system that can inspect the *structural DNA* of a link and predict its threat level in real-time, independent of historical blacklists.

### 1.2 Aims and Objectives
The primary objective of this project is to develop and implement **PhishGuard**, an end-to-end security platform addressing both technological detection and human vulnerability.
The specific objectives are:
1. To engineer a robust feature extraction algorithm that converts any raw URL into a set of numerical, security-oriented markers.
2. To train a Random Forest Classifier that categorizes links into "Safe" or "Phishing" with an accuracy exceeding 95%.
3. To design and deploy a lightweight, mobile-responsive Web portal using Python Flask and Bootstrap 5.
4. To implement a secure role-based database tracking scans, quiz scores, and admin audit events.
5. To construct an interactive educational center containing security articles, simulations, and quiz workflows that generate valid printable completion certificates.
6. To enable downloadable audit summaries in PDF format for record-keeping.

### 1.3 Scope of the Capstone Project
The scope of this B.Tech IT project covers the software engineering lifecycle: requirements gathering, algorithm engineering, ML model training, database schema mapping, backend control coding, frontend UI creation, and system testing. The platform is designed for deployment in corporate intranets or public educational web servers, serving as a unified security audit checkpoint and training dashboard.

---

## CHAPTER 2: LITERATURE SURVEY

### 2.1 Existing Phishing Detection Approaches
Phishing detection approaches in literature are broadly divided into three paradigms:
1. **List-based Methods (Blacklisting/Whitelisting):** Queries local or cloud databases. While fast, they fail to detect zero-day attacks.
2. **Visual Similarity Analysis:** Compares screenshots of suspicious sites with official brand logos. Highly CPU-intensive, prone to delays, and easily bypassed by rendering text via canvas overlays or changing CSS structures.
3. **Machine Learning-based (Heuristics):** Analyzes URL patterns, hosting registries, and HTML DOM structures. This project implements URL-based ML heuristics, which offer immediate feedback without the high computational cost of rendering web pages.

### 2.2 Critique of Blacklist-based Methods
Blacklists are reactive, not proactive. Studies indicate that a newly registered phishing domain is active for an average of 4-6 hours, whereas security crawling systems take up to 24-48 hours to identify, verify, and blacklist a URL. During this window, users remain entirely unprotected. By training an AI model to evaluate the structural composition of the URL directly, we enable predictive, real-time protection.

### 2.3 Machine Learning Algorithms Comparison
Prior literature was evaluated to select the most suitable classification algorithm:
- **Support Vector Machines (SVM):** High accuracy, but sensitive to parameter tuning and computationally expensive on large feature spaces.
- **Naive Bayes:** Extremely fast, but assumes absolute feature independence, which is untrue for URLs (e.g., URL length and subdomain counts are often correlated).
- **Random Forest Classifier:** An ensemble learning model that constructs multiple decision trees. It reduces overfitting, is highly robust against noisy data, and provides statistical confidence levels (via class probabilities). Therefore, the **Random Forest** was selected for PhishGuard.

---

## CHAPTER 3: SYSTEM REQUIREMENTS ANALYSIS

### 3.1 Functional Requirements
1. **User Authentication:** Sign up, hashed password storage, secure session logins, and logout.
2. **URL Scanner:** Accept link input, perform dynamic feature extraction, query the ML model, output predictions (Verdict, ML Confidence, Heuristic Risk), and log details.
3. **User Dashboard:** Display scan statistics (Total, Safe, Phishing) via interactive doughnut charts, and list personal historical logs.
4. **Awareness Module:** Read educational articles, review simulated emails, take a 10-question MCQ quiz, view explanations, and save results.
5. **Certificate Engine:** Generate unique verification certificate code and render a printable PDF/HTML card.
6. **PDF Compiler:** Allow users to download formal security audit reports of individual scans.
7. **Admin Control Board:** View registered users, delete accounts, inspect system logs, search all scans, and export raw CSV records.

### 3.2 Non-Functional Requirements
1. **Security:** Secure password hashing (Scrypt), SQL injection prevention via SQLAlchemy ORM, and RBAC page protections.
2. **Aesthetics:** Clean layout, modern Google typography, smooth card animations, and user-swappable Dark Mode.
3. **Performance:** URL scans must complete under 1.5 seconds.
4. **Portability:** Decoupled SQLite database fallback ensures zero-config runtime out-of-the-box.

### 3.3 Hardware and Software Specifications
- **Development Environment:**
  - OS: Windows 11 / Linux
  - IDE: Visual Studio Code / Antigravity IDE
  - Language: Python 3.10+, JavaScript, SQL
- **Libraries & Technologies:**
  - Web Server: Flask 3.0.2, Werkzeug, Jinja2
  - Database: MySQL 8.0 / SQLite 3
  - Data Science & ML: Scikit-learn, Pandas, NumPy, Pickle
  - Report Generation: ReportLab PDF Engine
  - UI/UX: Bootstrap 5, Chart.js, Mermaid.js

---

## CHAPTER 4: METHODOLOGY & SYSTEM DESIGN

### 4.1 High-Level Architecture
The platform is built on a standard three-tier MVC architecture:
1. **Presentation Layer (View):** Client browser executing HTML5, CSS themes, and Vanilla JS AJAX pipelines.
2. **Logic & API Layer (Controller):** Flask web server, custom URL feature extraction libraries, and the trained Random Forest classifier.
3. **Persistence Layer (Model):** MySQL/SQLite database storing relational schemas.

```
+-------------------------------------------------------------+
|                     Presentation Layer                      |
|           HTML5 | CSS Theme Variables | Bootstrap 5         |
|             Vanilla JS AJAX | Chart.js | Mermaid            |
+------------------------------+------------------------------+
                               | (HTTP Request / JSON API)
                               v
+-------------------------------------------------------------+
|                      Controller Layer                       |
|           Flask Web Server | Session Auth Manager           |
|         Heuristic Extractor | Random Forest Pickle          |
|                  ReportLab PDF Generator                    |
+------------------------------+------------------------------+
                               | (SQLAlchemy ORM)
                               v
+-------------------------------------------------------------+
|                      Persistence Layer                      |
|                  MySQL / SQLite Database                    |
+-------------------------------------------------------------+
```

### 4.2 URL Feature Engineering & Extraction
For each URL, we extract 9 key features, represented as a vector $X = [x_1, x_2, \dots, x_9]$:

1. **URL Length ($x_1$):**
   $$x_1 = \begin{cases} 1 & \text{if Length} \geq 54 \\ 0 & \text{otherwise} \end{cases}$$
2. **IP Address Domain ($x_2$):**
   $$x_2 = \begin{cases} 1 & \text{if domain matches IPv4/IPv6 pattern} \\ 0 & \text{otherwise} \end{cases}$$
3. **URL Shortener ($x_3$):**
   $$x_3 = \begin{cases} 1 & \text{if domain matches bit.ly, tinyurl, etc.} \\ 0 & \text{otherwise} \end{cases}$$
4. **Presence of '@' ($x_4$):**
   $$x_4 = \begin{cases} 1 & \text{if '@' is present in URL} \\ 0 & \text{otherwise} \end{cases}$$
5. **Redirection ($x_5$):**
   $$x_5 = \begin{cases} 1 & \text{if URL contains multiple '//' sequences} \\ 0 & \text{otherwise} \end{cases}$$
6. **Hyphen in Domain ($x_6$):**
   $$x_6 = \begin{cases} 1 & \text{if domain contains '-'} \\ 0 & \text{otherwise} \end{cases}$$
7. **Subdomain Count ($x_7$):**
   $$x_7 = \begin{cases} 1 & \text{if domain parts} \geq 3 \text{ (excluding 'www')} \\ 0 & \text{otherwise} \end{cases}$$
8. **SSL FINAL State ($x_8$):**
   $$x_8 = \begin{cases} 1 & \text{if scheme is 'http://'} \\ 0 & \text{if scheme is 'https://'} \end{cases}$$
9. **Suspicious Keywords ($x_9$):**
   $$x_9 = \text{Count of matching keywords in URL (e.g. login, secure, verify, bank)}$$

### 4.3 Random Forest Mathematical Foundation
A Random Forest is an ensemble of decision trees $\{T_1(x), T_2(x), \dots, T_B(x)\}$. During training, bootstrap aggregating (bagging) is used to select random subsets of data and features for each tree.

For a target URL feature vector $X$, each decision tree $T_b(X)$ casts a binary vote $\hat{y}_b \in \{0, 1\}$ (0 for Safe, 1 for Phishing). The final classification is determined by majority vote:
$$\hat{Y} = \text{mode} \{ T_1(X), T_2(X), \dots, T_B(X) \}$$

The classification confidence score is calculated from the class probability distribution:
$$P(Y = c | X) = \frac{1}{B} \sum_{b=1}^{B} I(T_b(X) = c)$$
$$\text{Confidence Score} = \max_c P(Y = c | X) \times 100\%$$

### 4.4 Relational Database Schema Design
The relational schema comprises four primary tables:
- **`users` Table:** Holds registered users details.
- **`scan_history` Table:** Stores url queries, prediction output, confidence score, threat index and extracted features.
- **`quiz_results` Table:** Records user quiz scores and certificate verification codes.
- **`admin_logs` Table:** Tracks admin operations.

---

## CHAPTER 5: SYSTEM IMPLEMENTATION

### 5.1 Model Training & Serializing Workflow
The file `ml_module/train_model.py` programmatically constructs a dataset of over 1,000 URLs, containing balanced ratios of safe and phishing targets. Features are extracted, and a `RandomForestClassifier(n_estimators=100)` is fit on the training data. The model is saved as `ml_module/phishing_model.pkl` using Python's `pickle` library, allowing the Flask backend to load and query it instantly.

### 5.2 Flask Routing & Controller APIs
The backend `app.py` exposes routing handlers:
- **`@app.route('/scan', methods=['POST'])`:** Receives URL link input, triggers feature extraction, runs the loaded ML model prediction, commits details to the database, and returns JSON.
- **`@app.route('/save-quiz', methods=['POST'])`:** Registers score metrics, constructs a unique certificate verification code, and saves details to the DB.

### 5.3 PDF Report Compilation Engine
The script `utils/pdf_generator.py` uses the **ReportLab** engine to generate a professional PDF report. It formats data into tables, adds custom color-coded threat assessments, and prints recommendations. The resulting PDF is returned to the user's browser as a downloadable attachment.

### 5.4 Frontend Aesthetic Layouts and Dark Mode
The frontend is built with clean CSS custom properties that toggle values based on the `[data-theme="dark"]` attribute. This enables a dark theme optimized for visibility, complete with smooth animations and transitions.

---

## CHAPTER 6: SYSTEM TESTING & EVALUATION

### 6.1 Model Performance Analytics
The Random Forest Classifier was trained and validated on an 80/20 train/test split. Evaluation results are summarized below:

- **Validation Classification Report:**
  - **Accuracy:** 98.63%
  - **Precision (Phishing):** 100.00%
  - **Recall (Phishing):** 97.46%
  - **F1-Score (Phishing):** 98.71%
  - **Precision (Safe):** 97.12%
  - **Recall (Safe):** 100.00%
  - **F1-Score (Safe):** 98.54%

- **Confusion Matrix:**
  - True Negatives (Safe correctly predicted): 101
  - False Positives (Safe misclassified): 0
  - False Negatives (Phishing misclassified): 3
  - True Positives (Phishing correctly predicted): 115

- **Feature Importances:**
  1. SSL Final State (HTTP vs HTTPS): 50.27%
  2. Suspicious Keywords count: 21.68%
  3. Prefix-Suffix (hyphens): 14.95%
  4. Subdomain Nesting count: 7.07%
  5. IP Address usage: 4.34%
  6. URL Length: 0.91%
  7. @ Symbol presence: 0.62%
  8. Shortening redirects: 0.15%

### 6.2 Unit and Integration Testing
- **Authentication Flows:** Tested registration with duplicate usernames/emails, password hashing verification, and session timeouts.
- **Role Permissions (RBAC):** Verified that standard users are blocked from `/admin` endpoints, redirecting them to the home page with an unauthorized warning.
- **SQL Injection Tests:** Attempted character escaping within form fields; parameters were correctly handled by SQLAlchemy.

### 6.3 Admin Audit Logging and Data Export
All admin actions, including user deletion and report exports, are logged in the `admin_logs` table with timestamps and IP addresses. Admins can export all scan records as a CSV file, which dynamically logs an action audit event.

---

## CHAPTER 7: AWARENESS & TRAINING LMS

### 7.1 Learning Curriculums and Phishing Blueprints
The platform provides educational articles detailing phishing tactics, alongside interactive email blueprints. These blueprints analyze common scams, such as account suspensions and password reset requests, pointing out key indicators of phishing.

### 7.2 Quiz Evaluation & Automated Certificate Generation
The interactive quiz consists of 10 MCQs. An option explanation is displayed after each submission. Users scoring 8/10 or higher can save their score, generating a unique verification code (e.g., `CERT-2026-6FE721`) that links to a printable certificate.

---

## CHAPTER 8: CONCLUSION & FUTURE SCOPE

### 8.1 Critical Summary of Accomplishments
The **PhishGuard** platform successfully integrates machine learning, dynamic feature extraction, database tracking, and user training. It delivers a modern, responsive web application with a verified ML accuracy of **98.63%**, a secure RBAC system, audit logs, and downloadable PDF reports.

### 8.2 Project Limitations
- **Dynamic Content Analysis:** The platform analyzes the URL structure, not the active webpage content. An attacker could host a phishing site on a legitimate domain using folder structures, which would bypass URL-only detection.
- **Third-Party Whitelists:** The system does not query active whitelists, meaning some edge cases may trigger false positives.

### 8.3 Future Enhancements
- **Dynamic Page Scraping:** Integrate BeautifulSoup to scrape the target webpage and analyze the HTML DOM (form fields, external links) for deeper classification.
- **Browser Extension:** Package the feature extraction and model inference engines into a Chrome extension for real-time browsing protection.

---

## REFERENCES
1. Scikit-learn: Machine Learning in Python, Pedregosa et al., JMLR 12, pp. 2825-2830, 2011.
2. Basnet, R., Mukkamala, S., & Sung, A. H. (2008). Detection of Phishing Attacks Using Machine Learning.
3. Provos, N., McNamee, D., & Wang, Y. (2007). The Ghost In The Browser: Analysis of Web-based Malware.
4. ReportLab PDF Library User Guide, ReportLab Europe Ltd.
5. Grinberg, M. (2018). Flask Web Development: Developing Web Applications with Python.
