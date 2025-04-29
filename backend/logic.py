from urllib.parse import urlparse
import socket
import ssl
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from googlesearch import search
import re

# --- Helper Functions ---
def is_valid_url(url):
    """Validate URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except:
        return False

# --- Detection Checks ---
def has_ip_address(url):
    """Check if URL contains an IP address."""
    try:
        host = urlparse(url).netloc.split(':')[0]  # Remove port if present
        socket.inet_aton(host)
        return True
    except (socket.error, ValueError):
        return False

def is_url_length_suspicious(url):
    """Check for excessively long URLs."""
    return len(url) >= 75

def has_at_symbol(url):
    """Check for '@' in URL (common in phishing)."""
    return "@" in url

def has_redirect(url):
    """Detect redirects (e.g., '//evil.com')."""
    try:
        return "//" in urlparse(url).path
    except:
        return False

def has_https_token(url):
    """Check if 'https' appears in the path (suspicious)."""
    try:
        return "https" in urlparse(url).path.lower()
    except:
        return False

def check_ssl_certificate(url):
    """Verify SSL certificate validity."""
    try:
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return bool(cert)
    except:
        return False

def domain_age(domain):
    """Check if domain is older than 1 year."""
    try:
        w = whois.whois(domain)
        if w.creation_date:
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            return (datetime.now() - creation).days >= 365
    except:
        return False

def google_index_check(url):
    """Check if domain is indexed by Google."""
    try:
        query = urlparse(url).netloc
        results = list(search(query, num_results=5, advanced=True))
        return any(query in r.url for r in results)
    except:
        return False

def has_iframe(url):
    """Detect iframes in page (potential phishing)."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        res = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        return bool(soup.find_all("iframe"))
    except:
        return False

def has_hyphens(url):
    """Check for excessive hyphens in domain."""
    return urlparse(url).netloc.count('-') >= 3

def is_typosquatting(domain):
    """Detect common typosquatting targets."""
    common_domains = ["google", "facebook", "amazon", "apple", "microsoft"]
    domain = domain.lower()
    return any(cd in domain and not domain.endswith(cd) for cd in common_domains)

# --- Core Detection ---
def detect_phishing(url):
    """Main phishing detection function."""
    if not is_valid_url(url):
        return {"error": "Invalid URL format"}, 400

    domain = urlparse(url).netloc
    logic_results = {
        "IP in URL": has_ip_address(url),
        "Long URL": is_url_length_suspicious(url),
        "@ symbol": has_at_symbol(url),
        "Redirect": has_redirect(url),
        "HTTPS in path": has_https_token(url),
        "SSL Valid": not check_ssl_certificate(url),  # Inverted: False = Suspicious
        "Domain Age < 1yr": not domain_age(domain),   # Inverted: True = Suspicious
        "Not Google Indexed": not google_index_check(url),
        "iFrame present": has_iframe(url),
        "Excessive Hyphens": has_hyphens(url),
        "Typosquatting": is_typosquatting(domain)
    }

    # Weighted scoring (adjust weights as needed)
    WEIGHTS = {
        "IP in URL": 2,
        "Typosquatting": 2,
        "SSL Valid": 1.5,
        "Domain Age < 1yr": 1,
        # ... other weights
    }
    
    score = sum(WEIGHTS.get(k, 1) for k, v in logic_results.items() if v)
    is_phishing = score >= 1  # Threshold adjustable

    return {
        "result": "Phishing" if is_phishing else "Legitimate",
        "details": logic_results,
        "score": round(score, 2),
        "url": url
    }