# 🔐 ZeroPhish – Phishing Detection Tool

ZeroPhish is a lightweight, open-source phishing detection system that analyzes URLs in real-time using rule-based heuristics. Designed for cybersecurity awareness and safe browsing, it helps users identify suspicious or malicious links before they fall victim to phishing attacks.

---

## 🚀 Features

- ✅ URL format validation
- 🔍 Detection of `@` symbols and redirect patterns
- 🔗 URL length check
- 🔒 SSL certificate verification
- 📆 Domain age detection via WHOIS
- 🔍 Google indexing status
- 🧩 Detection of `iframe` tags
- 🤖 Typosquatting pattern analysis
- ⚡ Real-time results via Flask API
- 🌐 Clean web interface (HTML + CSS)

---

## 🧠 How It Works

ZeroPhish performs a sequence of heuristic checks on a URL. If any suspicious traits are found (like an expired SSL certificate, hidden iframe, or suspicious length), it flags the URL and calculates a phishing risk score. The final risk level is displayed to the user in a clean web interface.

---

## 📂 Project Structure

