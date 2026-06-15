import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# Import our custom feature extractor
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml_module.features import get_feature_list

def generate_dataset():
    """
    Generates a balanced dataset of safe (benign) and phishing URLs
    for training the classifier.
    """
    print("Generating training dataset...")
    
    # 1. Base Benign URLs (Safe)
    benign_bases = [
        "https://www.google.com", "https://www.wikipedia.org", "https://github.com",
        "https://stackoverflow.com", "https://www.amazon.com", "https://www.microsoft.com",
        "https://www.nytimes.com", "https://www.cnn.com", "https://www.reddit.com",
        "https://www.linkedin.com", "https://www.apple.com", "https://www.netflix.com",
        "https://www.dropbox.com", "https://www.spotify.com", "https://www.medium.com",
        "https://www.yahoo.com", "https://www.ebay.com", "https://www.craiglist.org",
        "https://www.instagram.com", "https://www.facebook.com", "https://www.twitter.com",
        "https://www.pinterest.com", "https://www.quora.com", "https://www.salesforce.com"
    ]
    
    # Generate variations of benign URLs
    benign_urls = []
    for base in benign_bases:
        benign_urls.append(base)
        benign_urls.append(f"{base}/search?q=cybersecurity")
        benign_urls.append(f"{base}/about/help")
        benign_urls.append(f"{base}/index.html")
        benign_urls.append(f"{base}/home/user/profile")
        benign_urls.append(f"{base}/products/item123")
        benign_urls.append(f"{base}/blog/posts/2026/06")
        
    # Add more benign URLs
    more_benign = [
        "https://www.mit.edu", "https://www.harvard.edu", "https://www.stanford.edu",
        "https://www.nasa.gov", "https://www.nih.gov", "https://www.loc.gov",
        "https://www.bbc.co.uk", "https://www.reuters.com", "https://www.bloomberg.com",
        "https://www.oracle.com", "https://www.ibm.com", "https://www.intel.com"
    ]
    for base in more_benign:
        benign_urls.append(base)
        benign_urls.append(f"{base}/news")
        benign_urls.append(f"{base}/departments/it")
        
    # 2. Base Phishing URLs (Suspicious)
    # They usually have suspicious keywords, IP addresses, hyphens, subdomains, unsecure HTTP, shortening redirects
    phishing_templates = [
        "http://login-verify-paypal.com",
        "http://192.168.100.22/secure/login",
        "https://bit.ly/3xY7zhD",
        "http://amazon.update-account-security-verification.com/login",
        "http://netflix-billing-support.net",
        "http://signin.microsoft-online-service.org",
        "http://verify-bankofamerica.com/login.php",
        "http://secure-login-chase.com/verification",
        "http://recover-gmail-password.xyz",
        "http://apple-icloud-login.support",
        "http://ebay.signin-verify-update.com",
        "http://wellsfargo.account-alert-update.com",
        "http://secure.americanexpress.com.verify-billing.info",
        "http://facebook-security-verification.xyz/login",
        "http://steam-community-login.org/trade",
        "http://secure-banking-login.com",
        "http://10.20.30.40/bank/login",
        "http://tinyurl.com/y8z8fh3s",
        "http://cutt.ly/phish-target",
        "http://secure-login-credentials-update.net/signin.html"
    ]
    
    phishing_urls = []
    # Generate variations of phishing URLs
    for template in phishing_templates:
        phishing_urls.append(template)
        phishing_urls.append(f"{template}/webapps/home")
        phishing_urls.append(f"{template}/index.php?email=user@test.com")
        phishing_urls.append(f"{template}/secure/verify")
        phishing_urls.append(f"{template}/account/update/password")
        phishing_urls.append(f"{template}/billing/details")
        phishing_urls.append(f"{template}/signin.html?session=expired")
    
    # 3. Create synthetic variations to expand the dataset to ~500 items
    # Combine keywords and domain patterns to build more samples
    keywords = ["login", "secure", "verify", "update", "bank", "account", "signin", "password", "billing"]
    brands = ["paypal", "amazon", "netflix", "microsoft", "google", "apple", "chase", "bankofamerica"]
    tlds = [".com", ".net", ".org", ".info", ".xyz", ".support", ".co", ".cc"]
    
    for i in range(150):
        # Benign combination
        brand = np.random.choice(brands)
        tld = np.random.choice([".com", ".net", ".org"])
        benign_urls.append(f"https://www.{brand}{tld}/support/contact")
        benign_urls.append(f"https://www.{brand}{tld}/faq")
        
        # Phishing combination
        brand = np.random.choice(brands)
        keyword1 = np.random.choice(keywords)
        keyword2 = np.random.choice(keywords)
        tld = np.random.choice(tlds)
        
        # Pattern 1: http://brand-keyword.tld/keyword
        phishing_urls.append(f"http://{brand}-{keyword1}{tld}/{keyword2}")
        # Pattern 2: http://keyword1.keyword2.brand-verify.tld
        phishing_urls.append(f"http://{keyword1}.{keyword2}.{brand}-verify{tld}/login")
        # Pattern 3: IP address with brand path
        ip_parts = np.random.randint(1, 255, size=4)
        ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{ip_parts[3]}"
        phishing_urls.append(f"http://{ip}/{brand}/login.html")
        
    print(f"Generated {len(benign_urls)} Safe URLs and {len(phishing_urls)} Phishing URLs.")
    
    # Compile training set
    data = []
    # Safe URLs (label = 0)
    for url in benign_urls:
        features = get_feature_list(url)
        data.append(features + [0])
        
    # Phishing URLs (label = 1)
    for url in phishing_urls:
        features = get_feature_list(url)
        data.append(features + [1])
        
    # Column names
    columns = [
        "url_length", "having_ip_address", "shortening_service", "having_at_symbol",
        "double_slash_redirecting", "prefix_suffix", "having_sub_domain", "ssl_final_state",
        "suspicious_keywords", "label"
    ]
    
    df = pd.DataFrame(data, columns=columns)
    # Shuffle dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df

def train_model():
    """Trains and serializes the Random Forest model."""
    df = generate_dataset()
    
    # Save dataset to CSV for project deliverables
    os.makedirs(os.path.dirname(os.path.abspath(__file__)), exist_ok=True)
    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset.csv")
    df.to_csv(csv_path, index=False)
    print(f"Dataset saved to {csv_path}")
    
    # Split into features (X) and target (y)
    X = df.drop(columns=["label"])
    y = df["label"]
    
    # Split train and test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("Training Random Forest Classifier...")
    # Initialize Random Forest with 100 estimators
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print("\n--- MODEL PERFORMANCE ---")
    print(f"Test Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature importances
    importances = model.feature_importances_
    features_list = X.columns
    print("\nFeature Importances:")
    for f, imp in sorted(zip(features_list, importances), key=lambda x: x[1], reverse=True):
        print(f"- {f}: {imp * 100:.2f}%")
        
    # Serialize model to pickle
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing_model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    print(f"\nModel successfully saved to {model_path}")
    
if __name__ == "__main__":
    train_model()
