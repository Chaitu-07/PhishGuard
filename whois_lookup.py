import whois
from urllib.parse import urlparse
from datetime import datetime


# =====================================================
# Helper Functions
# =====================================================

def clean_value(value):
    """
    WHOIS libraries often return lists.
    This function converts them into a single value.
    """

    if isinstance(value, list):

        if len(value) > 0:
            return value[0]

        return None

    return value


def clean_date(date_value):
    """
    Returns a datetime object or None.
    """

    date_value = clean_value(date_value)

    if isinstance(date_value, datetime):
        return date_value

    return None


def format_date(date_value):
    """
    Formats datetime into readable form.
    """

    if date_value is None:
        return "Unavailable"

    return date_value.strftime("%d %B %Y")


def calculate_domain_age(created_date):
    """
    Calculates domain age in Years and Months.
    """

    if created_date is None:
        return "Unknown"

    today = datetime.now(created_date.tzinfo)

    years = today.year - created_date.year
    months = today.month - created_date.month

    if today.day < created_date.day:
        months -= 1

    if months < 0:
        years -= 1
        months += 12

    if years < 0:
        years = 0

    return f"{years} Years {months} Months"


# =====================================================
# WHOIS Lookup
# =====================================================

def get_whois_info(url):

    try:

        hostname = urlparse(url).netloc

        if hostname.startswith("www."):

            hostname = hostname[4:]

        info = whois.whois(hostname)

        created = clean_date(info.creation_date)

        expires = clean_date(info.expiration_date)

        registrar = clean_value(info.registrar)

        country = clean_value(getattr(info, "country", None))

        status = clean_value(getattr(info, "status", None))

        name_servers = getattr(info, "name_servers", None)

        if isinstance(name_servers, list):

            name_servers = ", ".join(name_servers[:3])

        elif name_servers is None:

            name_servers = "Unavailable"

        return {

            "domain": hostname,

            "registrar": registrar or "Unknown",

            "country": country or "Unknown",

            "creation_date": format_date(created),

            "expiration_date": format_date(expires),

            "domain_age": calculate_domain_age(created),

            "status": status or "Unavailable",

            "name_servers": name_servers,

            "age_years": (
                datetime.now(created.tzinfo).year - created.year
                if created else None
            )

        }

    except Exception:

        return {

            "domain": "Unavailable",

            "registrar": "Unavailable",

            "country": "Unavailable",

            "creation_date": "Unavailable",

            "expiration_date": "Unavailable",

            "domain_age": "Unknown",

            "status": "Unavailable",

            "name_servers": "Unavailable",

            "age_years": None

        }