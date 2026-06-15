# B.TECH VIVA-VOCE QUESTIONS & ANSWERS HANDBOOK
## PROJECT: AI-Powered Phishing Detection & Awareness Platform

This handbook compiles the top 20 questions frequently asked during the B.Tech IT Final Year Capstone Project Viva-voce examinations, complete with detailed answers.

---

### Q1: What is the primary objective of the "PhishGuard" platform?
**Answer:** The primary objective is to develop a unified cybersecurity checkpoint that detects zero-day phishing links using Machine Learning and Heuristic analysis, while simultaneously addressing human vulnerability. The platform provides real-time URL scanning, generates downloadable PDF audit reports, and features an interactive quiz system with automated certificate generation to train users to identify phishing cues.

---

### Q2: Why did you choose the Random Forest Classifier over other ML algorithms like SVM or Naive Bayes?
**Answer:** Random Forest is an ensemble learning method that constructs 100 decision trees during training. We chose it because:
1. **Reduces Overfitting:** By averaging predictions from multiple decision trees, it mitigates the risk of overfitting common in individual decision trees.
2. **Feature Independence:** Unlike Naive Bayes, Random Forest does not assume features are independent, which is crucial since URL parameters (like length and subdomain counts) are often correlated.
3. **Probability Scores:** It calculates the class probability based on decision tree votes, which we display as the "ML Classification Confidence Score."

---

### Q3: Explain the 9 key features extracted from a URL by your system.
**Answer:** The system analyzes 9 key features:
1. **URL Length:** Flagged as suspicious (1) if $\geq 54$ characters, else safe (0).
2. **IP Address Domain:** Flagged (1) if the domain is a raw IPv4/IPv6 address instead of a named host.
3. **URL Shortener:** Detects links obfuscated using shortening services (e.g., bit.ly, tinyurl).
4. **Presence of '@' Symbol:** Flagged (1) because browsers ignore everything before the '@' and load the domain that follows, which phishers exploit.
5. **Redirection (//):** Flagged (1) if the path contains multiple double slashes after the initial protocol.
6. **Prefix-Suffix (Hyphen):** Flagged (1) if the domain host contains hyphens, which are commonly used to mimic brand names (e.g., `paypal-secure.com`).
7. **Subdomain Count:** Flagged (1) if the domain contains three or more dot-separated parts (excluding `www`), indicating nested subdomains.
8. **SSL Final State:** Flagged as unsecure (1) if using HTTP, and safe (0) if using HTTPS.
9. **Suspicious Keywords:** Counts occurrences of phishing keywords (e.g., `login`, `secure`, `verify`, `bank`) in the URL.

---

### Q4: Why is the presence of an '@' symbol in a URL flagged as high risk?
**Answer:** In standard URL syntax, the characters preceding the `@` symbol are treated as user credentials, and the browser discards them. The browser only resolves and redirects to the domain name that follows the `@` symbol. Phishers exploit this by placing a legitimate domain name before the `@` and their malicious domain after it (e.g., `https://www.paypal.com@malicious-domain.com`), tricking users who only look at the beginning of the URL.

---

### Q5: What is the significance of the "SSL Final State" feature?
**Answer:** Legitimate organizations process credentials and sensitive data exclusively over secure connections using HTTPS. While phishers can obtain free SSL certificates, an unsecure HTTP URL is a strong indicator of a phishing attempt. The SSL final state acts as a primary classifier feature in our Random Forest model.

---

### Q6: How does your system handle database operations, and what happens if MySQL is offline?
**Answer:** We implemented a unified database config in `config.py` using **Flask-SQLAlchemy**.
1. **MySQL Setup:** The app can connect to a MySQL server by specifying the connection string in the `DATABASE_URL` environment variable.
2. **SQLite Fallback:** If the environment variable is not set, the system automatically falls back to a portable SQLite file database (`phishing_detector.db`) in the project root. This ensures the application runs out-of-the-box for evaluation.

---

### Q7: Detail the tables defined in your database schema.
**Answer:** The database schema consists of four relational tables:
1. **`users`:** Stores User IDs, unique usernames, unique emails, roles (`user` or `admin`), and hashed passwords.
2. **`scan_history`:** Tracks scanned URLs, predictions, confidence scores, risk levels, and JSON-encoded features.
3. **`quiz_results`:** Records quiz scores, total questions, completion times, and certificate codes.
4. **`admin_logs`:** Logs admin activities (e.g., user deletions, CSV exports) along with IP addresses for auditing.

---

### Q8: How is user password security managed in the backend?
**Answer:** User passwords are never stored in plaintext. We use the `werkzeug.security` library to implement password hashing:
1. **`generate_password_hash`:** Applied during registration to generate a salted password hash using the Scrypt algorithm.
2. **`check_password_hash`:** Used during login to securely verify the input password against the stored hash, protecting user credentials in the database.

---

### Q9: What is the role of the Heuristic Threat Risk Score, and how does it differ from the ML Confidence Score?
**Answer:** 
- The **ML Confidence Score** is the class probability calculated by the Random Forest model based on decision tree votes.
- The **Heuristic Threat Risk Score** (0-100) is a weighted score calculated from the presence of specific security risk factors in the URL structure. It provides an explainable threat metric alongside the ML model's prediction.

---

### Q10: How does the PDF report compiler handle extremely long URLs?
**Answer:** In the ReportLab library, long strings inside table cells can overflow page margins. We resolved this by wrapping the URL inside a `Paragraph` flowable and setting explicit column widths for the table. This forces the PDF engine to wrap the URL text onto multiple lines, keeping the document format intact.

---

### Q11: Explain how you implemented the Dark Mode theme.
**Answer:** We used CSS custom properties (variables) defined in `style.css`.
1. The global styles reference these variables (e.g., `var(--bg-primary)`, `var(--text-primary)`).
2. Toggling the dark mode button updates the body attribute to `[data-theme="dark"]`, which redefines the variables with dark theme colors.
3. The selected theme is saved in `localStorage` to persist the preference across page loads.

---

### Q12: Why did you choose Python Flask over Django?
**Answer:** Flask is a micro-framework that is lightweight, modular, and easy to set up. It provides the core routing and session handling features we need without the overhead of Django's default administrative tools and files. This makes it ideal for integrating custom machine learning models and utility libraries (like Scikit-learn and ReportLab).

---

### Q13: How did you evaluate the performance of your Random Forest model?
**Answer:** We evaluated the model on an 80/20 train/test split of our dataset. The key performance metrics are:
- **Accuracy:** 98.63%
- **Precision (Phishing):** 100% (No benign sites were misclassified as phishing).
- **Recall (Phishing):** 97.46% (Successfully identified 97.46% of phishing sites).
- **F1-Score:** 98.71%

---

### Q14: Explain the difference between DFD Level 0 and DFD Level 1.
**Answer:** 
- **DFD Level 0 (Context Diagram):** Represents the entire system as a single process block, showing only inputs and outputs from external actors (Users and Administrators).
- **DFD Level 1:** Breaks the system down into its core sub-processes (Authentication, URL Scanning, Quiz Controller, PDF Engine, Admin Panel) and maps the data flows between these processes and database tables.

---

### Q15: What is the purpose of the Admin Logs table in the database?
**Answer:** The `admin_logs` table tracks administrative actions for security auditing. When an administrator performs sensitive operations—such as deleting a user account or exporting system scan records—the system logs the admin ID, the action, the target user, the IP address, and the timestamp.

---

### Q16: How does the interactive quiz save scores and verify certificate eligibility?
**Answer:** 
1. The quiz is driven by a JavaScript state machine (`quiz.js`) that manages questions, scoring, and explanations.
2. Upon completion, if the score is $\geq 8/10$, the script sends a POST request to `/save-quiz` containing the score.
3. The Flask backend validates the session, generates a unique verification code, and saves the results to the database.
4. The user is redirected to the certificate page, which queries the database record to render a printable certificate.

---

### Q17: What are the primary limitations of the PhishGuard platform?
**Answer:** 
1. **URL-Only Analysis:** The system classifies links based on URL features and does not inspect the active webpage content (like HTML forms or DOM elements).
2. **Redirection Chains:** Obfuscated redirect scripts (e.g., meta refreshes, Javascript redirects) can hide the final destination URL from a static scanner.

---

### Q18: What is overfitting, and how does Random Forest address it?
**Answer:** Overfitting occurs when a machine learning model learns the training data too well, capturing noise and failing to generalize to new data. Random Forest addresses this through **bagging** (training each tree on a random sample of the data) and **feature bootstrapping** (selecting a random subset of features at each split). This ensures the individual trees are decorrelated, reducing variance when their predictions are averaged.

---

### Q19: How can this platform be enhanced for production deployment?
**Answer:** 
1. **Dynamic Web Scraping:** Integrate BeautifulSoup/Selenium to scrape the webpage content and inspect form actions, link distributions, and visible text for brand spoofing.
2. **Real-time Whitelists:** Query active whitelists (e.g., Alexa Top 10k domains) to automatically approve trusted domains, reducing false positives.
3. **Browser Extension:** Package the URL analysis features into a browser extension that blocks phishing pages before they load.

---

### Q20: How are database relationships modeled in Flask-SQLAlchemy?
**Answer:** We model relationships using foreign keys and SQLAlchemy relationships.
- The `User` model has a relationship (`db.relationship`) with `ScanHistory` and `QuizResult`.
- We use cascade deletes (`cascade="all, delete-orphan"`) so that when a user account is deleted, all their associated scan histories and quiz results are automatically removed from the database, maintaining referential integrity.
