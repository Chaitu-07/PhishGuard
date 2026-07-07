from flask import send_file
from pdf_generator import create_pdf_report
from datetime import datetime
import os
import time
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for

from detector import analyze_url
from database import db
from models import ScanHistory

from whois_lookup import get_whois_info
from ssl_checker import get_ssl_info
from dns_lookup import get_dns_info


app = Flask(__name__)

# -----------------------------------------------------
# Flask Configuration
# -----------------------------------------------------

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///phishguard.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "phishguard-secret-key"

db.init_app(app)

with app.app_context():
    db.create_all()


# -----------------------------------------------------
# Home Page
# -----------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# -----------------------------------------------------
# Analyze URL
# -----------------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():

    start_time = time.time()

    url = request.form.get("url", "").strip()

    if url == "":

        # Store latest scan data for PDF generation
        
        return render_template(
            "result.html",
            url="No URL Entered",
            score=0,
            verdict="Invalid URL",
            color="gray",
            reasons=[
                "Please enter a valid website URL."
            ],
            recommendations=[
                "Enter a complete URL beginning with http:// or https://"
            ]
        )

    # -----------------------------
    # Run Detection Engine
    # -----------------------------

    result = analyze_url(url)

    whois_data = get_whois_info(url)

    ssl_data = get_ssl_info(url)

    dns_data = get_dns_info(url)

    # -----------------------------
    # Improve Score using Domain Age
    # -----------------------------

    if whois_data["age_years"] is not None:

        if whois_data["age_years"] < 1:

            result["score"] = min(result["score"] + 20, 100)

            result["reasons"].append(
                "Domain is less than one year old."
            )

        elif whois_data["age_years"] < 3:

            result["score"] = min(result["score"] + 10, 100)

            result["reasons"].append(
                "Domain is relatively new."
            )

    # -----------------------------
    # Improve Score using SSL
    # -----------------------------

    if ssl_data["status"] != "Valid":

        result["score"] = min(result["score"] + 20, 100)

        result["reasons"].append(
            "SSL Certificate could not be verified."
        )

    # -----------------------------
    # Improve Score using DNS
    # -----------------------------

    if dns_data["reverse_dns"] == "Unavailable":

        result["score"] = min(result["score"] + 5, 100)

        result["reasons"].append(
            "Reverse DNS lookup unavailable."
        )

    # -----------------------------
    # Final Verdict
    # -----------------------------

    if result["score"] <= 20:

        result["verdict"] = "Safe"

        result["color"] = "green"

    elif result["score"] <= 50:

        result["verdict"] = "Suspicious"

        result["color"] = "orange"

    else:

        result["verdict"] = "Phishing"

        result["color"] = "red"

    # -----------------------------
    # Threat Level
    # -----------------------------

    if result["score"] <= 20:

        threat_level = "Low"

    elif result["score"] <= 50:

        threat_level = "Medium"

    elif result["score"] <= 75:

        threat_level = "High"

    else:

        threat_level = "Critical"

    # -----------------------------
    # Scan Time
    # -----------------------------

    scan_time = datetime.now().strftime(
        "%d %B %Y | %I:%M %p"
    )

    # -----------------------------
    # Analysis Time
    # -----------------------------

    analysis_time = round(
        time.time() - start_time,
        2
    )

    # -----------------------------
    # Security Summary
    # -----------------------------

    security_summary = {

        "https": "Enabled" if url.startswith("https://") else "Disabled",

        "ssl": ssl_data["status"],

        "whois": "Available"
        if whois_data["domain"] != "Unavailable"
        else "Unavailable",

        "dns": "Available"
        if dns_data["ip"] != "Unavailable"
        else "Unavailable",

        "domain_age": whois_data["domain_age"]

    }

    # -----------------------------
    # Detection Engine
    # -----------------------------

    detection_engine = [

        "HTTPS Analysis",

        "SSL Certificate Validation",

        "WHOIS Lookup",

        "DNS Resolution",

        "Domain Age Analysis",

        "URL Structure Analysis",

        "Suspicious Keyword Detection",

        "Top Level Domain Analysis"

    ]

    # -----------------------------
    # Save Scan History
    # -----------------------------

    history = ScanHistory(

        url=url,

        score=result["score"],

        verdict=result["verdict"]

    )

    db.session.add(history)

    db.session.commit()

    # -----------------------------
    # Render Result
    # -----------------------------

    # -----------------------------
    # Store latest scan for PDF
    # -----------------------------

    app.config["LAST_SCAN"] = {

        "url": url,
        "score": result["score"],
        "verdict": result["verdict"],
        "threat_level": threat_level,
        "reasons": result["reasons"],
        "recommendations": result["recommendations"],
        "whois_data": whois_data,
        "ssl_data": ssl_data,
        "dns_data": dns_data,
        "scan_time": scan_time

    }

    # -----------------------------
    # Render Result
    # -----------------------------

    return render_template(

        "result.html",

        url=url,

        score=result["score"],

        verdict=result["verdict"],

        color=result["color"],

        reasons=result["reasons"],

        recommendations=result["recommendations"],

        whois_data=whois_data,

        ssl_data=ssl_data,

        dns_data=dns_data,

        threat_level=threat_level,

        scan_time=scan_time,

        analysis_time=analysis_time,

        security_summary=security_summary,

        detection_engine=detection_engine

    )


# -----------------------------------------------------
# Scan History
# -----------------------------------------------------

@app.route("/history")
def history():

    scans = ScanHistory.query.order_by(
        ScanHistory.scan_time.desc()
    ).all()

    return render_template(
        "history.html",
        scans=scans
    )


# -----------------------------------------------------
# Clear History
# -----------------------------------------------------

@app.route("/clear-history")
def clear_history():

    ScanHistory.query.delete()

    db.session.commit()

    return redirect(url_for("history"))

# -----------------------------
# Download PDF Report
# -----------------------------

@app.route("/download-report")
def download_report():

    data = app.config.get("LAST_SCAN")

    if not data:

        return redirect(url_for("home"))

    os.makedirs("reports", exist_ok=True)

    filename = os.path.join(
        "reports",
        "PhishGuard_Report.pdf"
    )

    create_pdf_report(

        filename=filename,

        url=data["url"],

        score=data["score"],

        verdict=data["verdict"],

        threat_level=data["threat_level"],

        reasons=data["reasons"],

        recommendations=data["recommendations"],

        whois_data=data["whois_data"],

        ssl_data=data["ssl_data"],

        dns_data=data["dns_data"],

        scan_time=data["scan_time"]

    )

    return send_file(

        filename,

        as_attachment=True,

        download_name="PhishGuard_Report.pdf"

    )

# -----------------------------------------------------
# Error Pages
# -----------------------------------------------------

@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "404.html"
    ), 404


@app.errorhandler(500)
def internal_error(error):

    db.session.rollback()

    return render_template(
        "500.html"
    ), 500


# -----------------------------------------------------
# Run Application
# -----------------------------------------------------

if __name__ == "__main__":

    app.run(
        debug=True
    )