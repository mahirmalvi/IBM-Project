-- Seed file for seeding mock data into the Phishing Detection database

-- Seed Scan History
-- Note: User IDs 1 (admin) and 2 (user) are assumed to exist after python DB setup.
INSERT INTO scan_history (user_id, url, prediction, confidence_score, risk_score, features, created_at) VALUES
(2, 'https://www.google.com', 'Safe', 98.7, 5, '{"url_length": 22, "having_ip_address": 0, "shortening_service": 0, "having_at_symbol": 0, "double_slash_redirecting": 0, "prefix_suffix": 0, "having_sub_domain": 0, "ssl_final_state": 1, "suspicious_keywords": 0}', DATE_SUB(NOW(), INTERVAL 5 DAY)),
(2, 'http://paypal-security-login.com/webapps/home', 'Phishing', 91.2, 85, '{"url_length": 45, "having_ip_address": 0, "shortening_service": 0, "having_at_symbol": 0, "double_slash_redirecting": 0, "prefix_suffix": 1, "having_sub_domain": 1, "ssl_final_state": 0, "suspicious_keywords": 2}', DATE_SUB(NOW(), INTERVAL 4 DAY)),
(2, 'https://github.com/login', 'Safe', 95.4, 10, '{"url_length": 24, "having_ip_address": 0, "shortening_service": 0, "having_at_symbol": 0, "double_slash_redirecting": 0, "prefix_suffix": 0, "having_sub_domain": 0, "ssl_final_state": 1, "suspicious_keywords": 1}', DATE_SUB(NOW(), INTERVAL 3 DAY)),
(2, 'http://192.168.1.100/secure/bankofamerica/login.html', 'Phishing', 96.8, 95, '{"url_length": 53, "having_ip_address": 1, "shortening_service": 0, "having_at_symbol": 0, "double_slash_redirecting": 0, "prefix_suffix": 0, "having_sub_domain": 0, "ssl_final_state": 0, "suspicious_keywords": 3}', DATE_SUB(NOW(), INTERVAL 2 DAY)),
(2, 'https://bit.ly/3xY7zhD', 'Phishing', 74.3, 65, '{"url_length": 21, "having_ip_address": 0, "shortening_service": 1, "having_at_symbol": 0, "double_slash_redirecting": 0, "prefix_suffix": 0, "having_sub_domain": 0, "ssl_final_state": 1, "suspicious_keywords": 0}', DATE_SUB(NOW(), INTERVAL 1 DAY)),
(2, 'https://amazon.update-account-security-verification.com/login', 'Phishing', 98.1, 98, '{"url_length": 62, "having_ip_address": 0, "shortening_service": 0, "having_at_symbol": 0, "double_slash_redirecting": 0, "prefix_suffix": 1, "having_sub_domain": 1, "ssl_final_state": 1, "suspicious_keywords": 3}', NOW());

-- Seed Quiz Results
INSERT INTO quiz_results (user_id, score, total_questions, completed_at, certificate_code) VALUES
(2, 8, 10, DATE_SUB(NOW(), INTERVAL 3 DAY), 'CERT-2026-6FE721'),
(2, 10, 10, DATE_SUB(NOW(), INTERVAL 1 DAY), 'CERT-2026-9AA410');

-- Seed Admin Logs
INSERT INTO admin_logs (admin_id, action, target_user_id, ip_address, created_at) VALUES
(1, 'System Initialized', NULL, '127.0.0.1', DATE_SUB(NOW(), INTERVAL 6 DAY)),
(1, 'Registered default admin account', 1, '127.0.0.1', DATE_SUB(NOW(), INTERVAL 6 DAY)),
(1, 'Registered default demo user account', 2, '127.0.0.1', DATE_SUB(NOW(), INTERVAL 5 DAY)),
(1, 'Exported system scan report to CSV', NULL, '192.168.1.15', DATE_SUB(NOW(), INTERVAL 2 DAY));
