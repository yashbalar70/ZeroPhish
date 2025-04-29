from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import urlparse
import socket
import ssl
import whois
import requests
from bs4 import BeautifulSoup
from googlesearch import search
import re
import os
from logic import (
    has_ip_address,
    is_url_length_suspicious,
    has_at_symbol,
    has_redirect,
    has_https_token,
    check_ssl_certificate,
    domain_age,
    google_index_check,
    has_iframe,
    has_hyphens,
    is_typosquatting
)

app = Flask(__name__)
# Allow all origins for development (adjust for production)
CORS(app, resources={
    r"/check": {"origins": ["http://127.0.0.1:5500", "http://localhost:5500"]}
})

# Rate limiting (5 requests per minute per IP)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["5 per minute"]
)

def is_valid_url(url):
    """Validate URL format and basic sanity checks."""
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False
        # Basic regex to filter obviously malformed URLs
        return re.match(r'^https?://[^\s/$.?#].[^\s]*$', url) is not None
    except:
        return False

# Change the render_template line to:
@app.route('/')
def home():
    return render_template('../frontend/index.html')  # Path to your HTML file

@app.route("/check", methods=["POST"])
@limiter.limit("5 per minute")  # Apply rate limiting
def check():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        url = data.get("url", "").strip()
        if not url:
            return jsonify({"error": "URL is required"}), 400
            
        if not is_valid_url(url):
            return jsonify({"error": "Invalid URL format"}), 400

        # Basic phishing check before deep analysis
        if url.startswith(('http://', 'http:/', 'http:')) and not url.startswith('http://'):
            return jsonify({
                "result": "Phishing",
                "warning": "URL manipulation detected",
                "score": 3
            })

        result = detect_phishing(url)
        return jsonify(result)

    except Exception as e:
        app.logger.error(f"Error processing request: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

def detect_phishing(url):
    """Enhanced phishing detection with timeout safety."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        logic_results = {
            "IP in URL": has_ip_address(url),
            "Long URL": is_url_length_suspicious(url),
            "@ symbol": has_at_symbol(url),
            "Redirect": has_redirect(url),
            "HTTPS in path": has_https_token(url),
            "SSL Valid": check_ssl_certificate(url),
            "Domain Age > 1yr": domain_age(domain),
            "Google Indexed": google_index_check(url),
            "iFrame present": has_iframe(url),
            "Excessive Hyphens": has_hyphens(url),
            "Typosquatting": is_typosquatting(domain)
        }

        score = sum([
            2 if logic_results["IP in URL"] else 0,  # Higher weight for IP
            1 if logic_results["Long URL"] else 0,
            1.5 if logic_results["@ symbol"] else 0,
            # ... other weighted scores
            sum(1 for k, v in logic_results.items() if v and k not in ["IP in URL", "@ symbol"])
        ])

        is_phishing = score >= 1  # Adjusted threshold

        return {
            "result": "Phishing" if is_phishing else "Legitimate",
            "details": logic_results,
            "score": score,
            "url": url  # Return the analyzed URL for reference
        }

    except requests.exceptions.Timeout:
        return {"error": "Request timeout"}, 408
    except Exception as e:
        app.logger.error(f"Detection error: {str(e)}")
        return {"error": "Detection failed"}, 500

# ... (keep your existing helper functions like has_ip_address, etc.) ...

if __name__ == "__main__":
    app.run(port=5001)
