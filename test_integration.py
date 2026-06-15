import os
import json
import unittest
from datetime import datetime

# Setup paths for importing custom modules
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from ml_module.features import extract_features, get_feature_list, calculate_heuristic_risk
from utils.pdf_generator import generate_scan_pdf

# Mock scan record class matching SQL model fields
class MockScanHistory:
    def __init__(self, id, url, prediction, confidence_score, risk_score, features, created_at=None):
        self.id = id
        self.url = url
        self.prediction = prediction
        self.confidence_score = confidence_score
        self.risk_score = risk_score
        self.features = features
        self.created_at = created_at or datetime.utcnow()

class TestPhishingDetectorIntegration(unittest.TestCase):
    
    def test_01_feature_extraction(self):
        """Test URL Feature Extraction parameters"""
        print("\nTesting URL Feature Extraction...")
        url = "http://login-verify-paypal.com/update-security"
        feats = extract_features(url)
        
        self.assertIn("url_length", feats)
        self.assertIn("ssl_final_state", feats)
        self.assertIn("suspicious_keywords", feats)
        
        # http should trigger ssl_final_state = 1
        self.assertEqual(feats["ssl_final_state"], 1)
        # login/verify/update should trigger keyword count > 0
        self.assertGreater(feats["suspicious_keywords"], 0)
        
        feat_list = get_feature_list(url)
        self.assertEqual(len(feat_list), 9)
        print("Feature Extraction Passed.")

    def test_02_risk_heurisitic_calculation(self):
        """Test the heuristic risk calculator"""
        print("\nTesting Heuristic Risk Calculation...")
        safe_url = "https://www.google.com"
        phish_url = "http://192.168.1.1/login-verify-update-paypal-security.html"
        
        safe_feats = extract_features(safe_url)
        safe_risk = calculate_heuristic_risk(safe_url, safe_feats)
        
        phish_feats = extract_features(phish_url)
        phish_risk = calculate_heuristic_risk(phish_url, phish_feats)
        
        print(f"Safe URL Risk Score: {safe_risk}/100")
        print(f"Phishing URL Risk Score: {phish_risk}/100")
        
        self.assertLess(safe_risk, 30)
        self.assertGreater(phish_risk, 70)
        print("Heuristic Risk Calculation Passed.")

    def test_03_pdf_generation(self):
        """Test PDF Report generation using ReportLab"""
        print("\nTesting PDF Report Generation...")
        features_json = json.dumps(extract_features("http://paypal-restricted.com/login"))
        
        mock_scan = MockScanHistory(
            id=101,
            url="http://paypal-restricted.com/login",
            prediction="Phishing",
            confidence_score=94.5,
            risk_score=85,
            features=features_json
        )
        
        pdf_data = generate_scan_pdf(mock_scan, "demo_user")
        self.assertGreater(len(pdf_data), 0)
        
        # Save sample pdf report to static/uploads for manual inspection if needed
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
        os.makedirs(output_dir, exist_ok=True)
        pdf_path = os.path.join(output_dir, "test_report_scan_101.pdf")
        with open(pdf_path, "wb") as f:
            f.write(pdf_data)
            
        print(f"Sample PDF successfully saved to: {pdf_path}")
        print("PDF Report Generation Passed.")

    def test_04_bcrypt_password_hashing(self):
        """Test registration bcrypt hashing and check helpers"""
        from app import hash_password, check_password
        print("\nTesting Bcrypt password hashing...")
        raw_password = "my_secure_cyber_password_123"
        hashed = hash_password(raw_password)
        
        # Verify it has standard bcrypt signature ($2b$)
        self.assertTrue(hashed.startswith("$2b$"))
        
        # Verify checking works
        self.assertTrue(check_password(hashed, raw_password))
        self.assertFalse(check_password(hashed, "wrong_password"))
        print("Bcrypt Password Hashing Passed.")

if __name__ == "__main__":
    unittest.main()
