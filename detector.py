import re
import validators
from urllib.parse import urlparse

# =====================================================
# Suspicious Keywords
# =====================================================

SUSPICIOUS_KEYWORDS = [

    "login",
    "verify",
    "verification",
    "signin",
    "sign-in",
    "secure",
    "update",
    "confirm",
    "password",
    "account",
    "bank",
    "wallet",
    "paypal",
    "invoice",
    "billing",
    "payment",
    "gift",
    "reward",
    "bonus",
    "otp",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "crypto",
    "bitcoin"

]

# =====================================================
# URL Shorteners
# =====================================================

SHORTENERS = [

    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "buff.ly"

]

# =====================================================
# Suspicious TLDs
# =====================================================

SUSPICIOUS_TLDS = [

    ".xyz",
    ".top",
    ".click",
    ".work",
    ".support",
    ".zip",
    ".gq",
    ".cf",
    ".ml",
    ".tk"

]


# =====================================================
# Helper Functions
# =====================================================

def add_reason(reasons, text):

    if text not in reasons:

        reasons.append(text)


def increase(score, amount):

    return min(score + amount, 100)


# =====================================================
# Detection Engine
# =====================================================

def analyze_url(url):

    score = 0

    reasons = []

    # ---------------------------------------
    # URL Validation
    # ---------------------------------------

    if not validators.url(url):

        return {

            "score": 0,

            "verdict": "Invalid URL",

            "color": "gray",

            "reasons": [

                "The URL entered is invalid."

            ],

            "recommendations": [

                "Enter a complete URL beginning with http:// or https://"

            ]

        }

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    full_url = url.lower()

    # ---------------------------------------
    # HTTPS Check
    # ---------------------------------------

    if parsed.scheme != "https":

        score = increase(score, 25)

        add_reason(

            reasons,

            "Website is not using HTTPS."

        )

    # ---------------------------------------
    # URL Length
    # ---------------------------------------

    length = len(url)

    if length > 100:

        score = increase(score, 15)

        add_reason(

            reasons,

            "URL is extremely long."

        )

    elif length > 75:

        score = increase(score, 10)

        add_reason(

            reasons,

            "URL is unusually long."

        )

    # ---------------------------------------
    # IP Address Detection
    # ---------------------------------------

    if re.search(

        r"\d+\.\d+\.\d+\.\d+",

        domain

    ):

        score = increase(score, 20)

        add_reason(

            reasons,

            "Domain uses an IP address."

        )

    # ---------------------------------------
    # @ Symbol
    # ---------------------------------------

    if "@" in url:

        score = increase(score, 15)

        add_reason(

            reasons,

            "Contains '@' symbol."

        )

    # ---------------------------------------
    # Double Slash Redirect
    # ---------------------------------------

    if "//" in full_url[8:]:

        score = increase(score, 10)

        add_reason(

            reasons,

            "Contains suspicious redirect ('//')."

        )

    # ---------------------------------------
    # Encoded Characters
    # ---------------------------------------

    if "%" in url:

        score = increase(score, 8)

        add_reason(

            reasons,

            "Contains encoded characters."

        )

    # ---------------------------------------
    # Excessive Hyphens
    # ---------------------------------------

    if domain.count("-") >= 2:

        score = increase(score, 10)

        add_reason(

            reasons,

            "Too many hyphens in domain."

        )

    # ---------------------------------------
    # Too Many Dots
    # ---------------------------------------

    if domain.count(".") >= 3:

        score = increase(score, 10)

        add_reason(

            reasons,

            "Contains multiple subdomains."

        )

    # ---------------------------------------
    # URL Shorteners
    # ---------------------------------------

    for shortener in SHORTENERS:

        if shortener in domain:

            score = increase(score, 20)

            add_reason(

                reasons,

                "Uses a URL shortening service."

            )

            break

    # ---------------------------------------
    # Suspicious Keywords
    # ---------------------------------------

    keyword_count = 0

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in full_url:

            keyword_count += 1

            score = increase(score, 5)

            add_reason(

                reasons,

                f"Contains suspicious keyword '{keyword}'."

            )

    if keyword_count >= 4:

        score = increase(score, 10)

        add_reason(

            reasons,

            "Contains many phishing-related keywords."

        )

    # ---------------------------------------
    # Suspicious Top Level Domain
    # ---------------------------------------

    for tld in SUSPICIOUS_TLDS:

        if domain.endswith(tld):

            score = increase(score, 15)

            add_reason(

                reasons,

                f"Uses suspicious top-level domain ({tld})."

            )

            break

    # ---------------------------------------
    # Excessive Numbers
    # ---------------------------------------

    numbers = len(re.findall(r"\d", domain))

    if numbers >= 6:

        score = increase(score, 8)

        add_reason(

            reasons,

            "Domain contains many numeric characters."

        )

    # ---------------------------------------
    # Random-looking Domain
    # ---------------------------------------

    letters = re.findall(r"[a-z]", domain)

    consonants = re.findall(r"[bcdfghjklmnpqrstvwxyz]", domain)

    if len(consonants) >= 8:

        score = increase(score, 6)

        add_reason(

            reasons,

            "Domain appears randomly generated."

        )

    # ---------------------------------------
    # Long Domain Name
    # ---------------------------------------

    domain_name = domain.split(".")[0]

    if len(domain_name) > 25:

        score = increase(score, 8)

        add_reason(

            reasons,

            "Domain name is unusually long."

        )

    # ---------------------------------------
    # Suspicious Port
    # ---------------------------------------

    if parsed.port:

        if parsed.port not in [80, 443]:

            score = increase(score, 10)

            add_reason(

                reasons,

                f"Uses uncommon port ({parsed.port})."

            )

    # ---------------------------------------
    # Query Parameters
    # ---------------------------------------

    if "=" in parsed.query:

        parameter_count = parsed.query.count("=")

        if parameter_count >= 4:

            score = increase(score, 6)

            add_reason(

                reasons,

                "Contains many URL parameters."

            )

    # ---------------------------------------
    # File Extensions
    # ---------------------------------------

    suspicious_extensions = [

        ".exe",
        ".scr",
        ".zip",
        ".rar",
        ".js"

    ]

    for ext in suspicious_extensions:

        if full_url.endswith(ext):

            score = increase(score, 12)

            add_reason(

                reasons,

                f"URL points to a downloadable file ({ext})."

            )

            break

    # ---------------------------------------
    # Login Page Detection
    # ---------------------------------------

    login_words = [

        "login",
        "signin",
        "verify",
        "authenticate"

    ]

    for word in login_words:

        if word in full_url:

            score = increase(score, 5)

            add_reason(

                reasons,

                "Requests account authentication."

            )

            break

    # ---------------------------------------
    # Excessive Slashes
    # ---------------------------------------

    if full_url.count("/") > 6:

        score = increase(score, 5)

        add_reason(

            reasons,

            "Contains many path segments."

        )

    # ---------------------------------------
    # URL Length Bonus Check
    # ---------------------------------------

    if len(full_url) > 150:

        score = increase(score, 10)

        add_reason(

            reasons,

            "Very long URL detected."

        )

    # ---------------------------------------
    # Cap Final Score
    # ---------------------------------------

    score = min(score, 100)

    # =====================================================
    # Final Verdict
    # =====================================================

    if score <= 20:

        verdict = "Safe"

        color = "green"

    elif score <= 50:

        verdict = "Suspicious"

        color = "orange"

    else:

        verdict = "Phishing"

        color = "red"

    # =====================================================
    # Threat Level
    # =====================================================

    if score <= 20:

        threat_level = "Low"

    elif score <= 50:

        threat_level = "Medium"

    elif score <= 75:

        threat_level = "High"

    else:

        threat_level = "Critical"

    # =====================================================
    # Recommendations
    # =====================================================

    recommendations = []

    if verdict == "Safe":

        recommendations.extend([

            "No major phishing indicators were detected.",

            "Always verify the website before entering sensitive information.",

            "Keep your browser and antivirus software updated.",

            "Ensure the website URL is correct before logging in."

        ])

    elif verdict == "Suspicious":

        recommendations.extend([

            "Proceed with caution before interacting with this website.",

            "Verify the domain spelling carefully.",

            "Avoid entering usernames, passwords, or OTPs unless you trust the site.",

            "Check the SSL certificate before continuing.",

            "Search for the official website if you are unsure."

        ])

    else:

        recommendations.extend([

            "Avoid entering any personal or financial information.",

            "Do not download files from this website.",

            "Leave the website immediately if it requests credentials unexpectedly.",

            "Verify the URL through the official company website.",

            "Report the website if you believe it is phishing."

        ])

    # =====================================================
    # Default Reason
    # =====================================================

    if len(reasons) == 0:

        reasons.append(

            "No suspicious indicators were detected."

        )

    # =====================================================
    # Detection Statistics
    # =====================================================

    detection_summary = {

        "url_analysis": True,

        "keyword_analysis": True,

        "tld_analysis": True,

        "structure_analysis": True,

        "shortener_analysis": True,

        "subdomain_analysis": True,

        "ip_analysis": True

    }

    # =====================================================
    # Return Result
    # =====================================================

    return {

        "score": score,

        "verdict": verdict,

        "color": color,

        "threat_level": threat_level,

        "reasons": reasons,

        "recommendations": recommendations,

        "detection_summary": detection_summary

    }            