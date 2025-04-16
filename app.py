import re
import requests
import whois
from urllib.parse import urlparse
from datetime import datetime

def is_ip_address(domain):
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))

def has_suspicious_chars(url):
    return '@' in url or '-' in url or url.count('.') > 3

def has_phishing_keywords(url):
    keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking']
    return any(keyword in url.lower() for keyword in keywords)

def get_domain_age(domain):
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age = (datetime.now() - creation_date).days
            return age
    except:
        return None
    return None

def check_url_live(url):
    try:
        response = requests.head(url, timeout=5)
        return response.status_code
    except:
        return None

def scan_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    print(f"Scanning URL: {url}")
    suspicious_score = 0
    reasons = []

    if is_ip_address(domain):
        suspicious_score += 2
        reasons.append("IP address used in URL")

    if has_suspicious_chars(url):
        suspicious_score += 1
        reasons.append("Suspicious characters found")

    if has_phishing_keywords(url):
        suspicious_score += 2
        reasons.append("Contains phishing-related keywords")

    age = get_domain_age(domain)
    if age is not None and age < 180:
        suspicious_score += 1
        reasons.append("Newly registered domain (< 6 months)")

    status = check_url_live(url)
    if status is None:
        suspicious_score += 1
        reasons.append("URL not reachable")

    print("\n[Result]")
    if suspicious_score >= 4:
        print("⚠️ Potential phishing link detected!")
    else:
        print("✅ URL looks relatively safe.")
    
    print("Reasons:")
    for reason in reasons:
        print(f"- {reason}")

    print("\n---")

# Example usage
if __name__ == "__main__":
    test_url = input("Enter a URL to scan: ")
    scan_url(test_url)
