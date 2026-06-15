import re
from urllib.parse import urlparse

# List of common URL shortening services
SHORTENING_SERVICES = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.ny|lnkd\.in|" \
                      r"db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tiny\.cc|ow\.ly|bit\.ly|ity\.im|" \
                      r"q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.ly|u\.nu|t2m\.io"

# List of suspicious keywords commonly used in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "verify", "update", "bank", "account", "signin", "submit",
    "webapps", "wp-admin", "wp-content", "paypal", "amazon", "netflix", "apple",
    "microsoft", "google", "credential", "password", "recover", "validation"
]

def check_ip_address(domain: str) -> int:
    """Check if domain name is an IP address (IPv4 or IPv6)."""
    # Regex for IPv4
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    # Regex for IPv6
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$|" \
                   r"^([0-9a-fA-F]{1,4}:){1,7}:$|" \
                   r"^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|" \
                   r"^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|" \
                   r"^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|" \
                   r"^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|" \
                   r"^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|" \
                   r"^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|" \
                   r"^:((:[0-9a-fA-F]{1,4}){1,7}|:)$"
    
    if re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain):
        return 1
    return 0

def extract_features(url: str) -> dict:
    """
    Extracts 9 binary/numeric features from a URL.
    Returns a dictionary of features.
    """
    # Clean URL and ensure scheme is present for parsing
    url = url.strip()
    if not re.match(r'^https?://', url, re.IGNORECASE):
        # Default to http for parsing structure if not present
        parsed_url = urlparse("http://" + url)
    else:
        parsed_url = urlparse(url)
        
    domain = parsed_url.netloc
    path = parsed_url.path
    
    # 1. URL Length (Phishing URLs are often very long to hide subdomains or targets)
    # Threshold: >= 54 characters is flagged as suspicious (1), else 0
    url_length = 1 if len(url) >= 54 else 0

    # 2. Having IP Address
    having_ip_address = check_ip_address(domain)

    # 3. Shortening Service
    shortening_service = 1 if re.search(SHORTENING_SERVICES, domain, re.IGNORECASE) else 0

    # 4. Having @ Symbol (Used to ignore everything before it, leading to redirection)
    having_at_symbol = 1 if "@" in url else 0

    # 5. Double Slash Redirecting (Presence of '//' in the path, indicating redirection)
    # The first double slash is for http:// or https://, check for others
    double_slash_redirecting = 1 if url.count("//") > 1 else 0

    # 6. Prefix/Suffix (Phishing domains often use hyphens, e.g., paypal-secure.com)
    prefix_suffix = 1 if "-" in domain else 0

    # 7. Having Subdomain (Multi-level subdomains are common in phishing)
    # Split domain by dots. e.g., login.paypal.com has 3 parts.
    # Exclude empty strings and 'www'
    domain_parts = [part for part in domain.split('.') if part and part.lower() != 'www']
    # If parts >= 3 (e.g. login.secure.paypal.com), flag it as suspicious (1), else 0
    having_sub_domain = 1 if len(domain_parts) >= 3 else 0

    # 8. SSL Final State (HTTP is unsecure, HTTPS is generally secure)
    # Flag HTTP as 1 (suspicious) and HTTPS as 0 (safe)
    ssl_final_state = 0 if url.lower().startswith("https://") else 1

    # 9. Suspicious Keywords (Count occurrences of phishing keywords in URL)
    keyword_count = 0
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            keyword_count += 1
    # We can cap it at 3 or keep raw count
    suspicious_keywords = keyword_count

    # 10. Excessive Special Characters
    special_char_count = len(re.findall(r'[?=\-&@%+_.]', url))
    excessive_special_chars = 1 if special_char_count >= 8 else 0

    return {
        "url_length": url_length,
        "having_ip_address": having_ip_address,
        "shortening_service": shortening_service,
        "having_at_symbol": having_at_symbol,
        "double_slash_redirecting": double_slash_redirecting,
        "prefix_suffix": prefix_suffix,
        "having_sub_domain": having_sub_domain,
        "ssl_final_state": ssl_final_state,
        "suspicious_keywords": suspicious_keywords,
        "excessive_special_chars": excessive_special_chars
    }

def get_feature_list(url: str) -> list:
    """
    Extracts features and returns them as an ordered list of values
    suitable for model input.
    """
    feats = extract_features(url)
    return [
        feats["url_length"],
        feats["having_ip_address"],
        feats["shortening_service"],
        feats["having_at_symbol"],
        feats["double_slash_redirecting"],
        feats["prefix_suffix"],
        feats["having_sub_domain"],
        feats["ssl_final_state"],
        feats["suspicious_keywords"]
    ]

def calculate_heuristic_risk(url: str, feats: dict) -> int:
    """
    Calculate a heuristic risk score (0-100) based on extracted features.
    Provides a fallback/explainability metric alongside ML confidence.
    """
    score = 0
    # Assign weights to features
    weights = {
        "url_length": 10,
        "having_ip_address": 15,
        "shortening_service": 10,
        "having_at_symbol": 15,
        "double_slash_redirecting": 10,
        "prefix_suffix": 10,
        "having_sub_domain": 10,
        "ssl_final_state": 15,
        "suspicious_keywords": 15,  # 15 per keyword, capped
        "excessive_special_chars": 10
    }
    
    score += feats["url_length"] * weights["url_length"]
    score += feats["having_ip_address"] * weights["having_ip_address"]
    score += feats["shortening_service"] * weights["shortening_service"]
    score += feats["having_at_symbol"] * weights["having_at_symbol"]
    score += feats["double_slash_redirecting"] * weights["double_slash_redirecting"]
    score += feats["prefix_suffix"] * weights["prefix_suffix"]
    score += feats["having_sub_domain"] * weights["having_sub_domain"]
    score += feats["ssl_final_state"] * weights["ssl_final_state"]
    score += feats.get("excessive_special_chars", 0) * weights["excessive_special_chars"]
    
    keyword_score = feats["suspicious_keywords"] * weights["suspicious_keywords"]
    score += min(keyword_score, 30) # cap keyword score at 30
    
    return min(score, 100)
