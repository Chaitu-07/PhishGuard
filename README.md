# 🛡️ PhishGuard

> A modern phishing website detection system built with **Flask** that analyzes URLs using multiple security checks including URL analysis, WHOIS lookup, SSL certificate validation, DNS lookup, and risk scoring.

---

## 📌 Overview

PhishGuard is a cybersecurity web application that helps users identify potentially malicious or phishing websites before visiting them. The application performs multiple security checks and presents the results in an interactive dashboard along with recommendations and downloadable PDF reports.

---

## ✨ Features

### 🔍 URL Analysis
- URL structure inspection
- Suspicious keyword detection
- URL length analysis
- URL shortener detection
- Multiple subdomain detection
- Suspicious Top-Level Domain (TLD) detection

### 🔒 SSL Certificate Analysis
- SSL certificate validation
- Certificate issuer
- Common Name (CN)
- Certificate validity period
- Days remaining until expiration
- TLS version detection

### 🌐 WHOIS Lookup
- Domain registrar
- Domain creation date
- Expiration date
- Domain age calculation
- Country information

### 🌍 DNS Analysis
- Hostname lookup
- IPv4 address
- Reverse DNS lookup
- Protocol detection
- Port identification
- Top-Level Domain (TLD)
- Subdomain detection

### 📊 Risk Assessment
- Risk score calculation (0–100)
- Threat level classification
- Safe / Suspicious / Phishing verdict
- Threat indicators
- Security recommendations

### 📁 Additional Features
- Scan history
- Search scan history
- Dashboard statistics
- PDF report generation
- Modern cybersecurity-themed interface
- Responsive design
---

# 🛠️ Tech Stack

### Backend
- Python
- Flask
- Flask-SQLAlchemy
- SQLite

### Frontend
- HTML5
- CSS3
- JavaScript
- Bootstrap Icons

### Python Libraries
- validators
- python-whois
- socket
- ssl
- tldextract
- ReportLab

---

# 📂 Project Structure

```
PhishGuard
│
├── static
│   ├── css
│   ├── js
│   └── images
│
├── templates
│   ├── base.html
│   ├── index.html
│   ├── result.html
│   ├── history.html
│   ├── 404.html
│   └── 500.html
│
├── reports
│
├── app.py
├── detector.py
├── dns_lookup.py
├── ssl_checker.py
├── whois_lookup.py
├── pdf_generator.py
├── database.py
├── models.py
├── requirements.txt
├── README.md
└── .gitignore
```
---

## Install Dependencies

Flask
Flask-SQLAlchemy
validators
tldextract
python-whois
cryptography
reportlab

---

# 🧠 Detection Workflow

```
User enters URL
        │
        ▼
Validate URL
        │
        ▼
Rule-Based URL Analysis
        │
        ▼
SSL Certificate Check
        │
        ▼
WHOIS Lookup
        │
        ▼
DNS Lookup
        │
        ▼
Calculate Risk Score
        │
        ▼
Generate Verdict
        │
        ▼
Display Report
        │
        ▼
Save Scan History
        │
        ▼
Generate PDF Report
```

---

# 🚀 Future Improvements

- Machine Learning-based phishing detection
- VirusTotal API integration
- Google Safe Browsing API
- Email phishing detection
- Browser extension
- User authentication
- User dashboard
- Threat intelligence integration
- Live domain reputation analysis
- Dark mode customization

---

# 🎯 Learning Outcomes

This project demonstrates knowledge of:

- Flask Web Development
- Cybersecurity Fundamentals
- URL Security Analysis
- WHOIS & DNS Lookups
- SSL Certificate Inspection
- SQLite Database Integration
- PDF Report Generation
- Responsive UI Design
- Git & GitHub

---

# 📜 License

This project is intended for educational and portfolio purposes.
