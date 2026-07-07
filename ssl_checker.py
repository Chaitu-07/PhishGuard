import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime


# =====================================================
# SSL Certificate Lookup
# =====================================================

def get_ssl_info(url):

    try:

        hostname = urlparse(url).netloc

        if hostname.startswith("www."):

            hostname = hostname[4:]

        context = ssl.create_default_context()

        with context.wrap_socket(

            socket.socket(socket.AF_INET),

            server_hostname=hostname

        ) as connection:

            connection.settimeout(5)

            connection.connect((hostname, 443))

            certificate = connection.getpeercert()

            tls_version = connection.version()

        issuer = dict(x[0] for x in certificate["issuer"])

        subject = dict(x[0] for x in certificate["subject"])

        valid_from = datetime.strptime(

            certificate["notBefore"],

            "%b %d %H:%M:%S %Y %Z"

        )

        valid_until = datetime.strptime(

            certificate["notAfter"],

            "%b %d %H:%M:%S %Y %Z"

        )

        days_left = (valid_until - datetime.utcnow()).days

        # ------------------------------------
        # Certificate Status
        # ------------------------------------

        if days_left < 0:

            status = "Expired"

        else:

            status = "Valid"

        # ------------------------------------
        # Self Signed
        # ------------------------------------

        self_signed = issuer == subject

        return {

            "status": status,

            "common_name": subject.get(

                "commonName",

                hostname

            ),

            "organization": subject.get(

                "organizationName",

                "Unavailable"

            ),

            "issuer": issuer.get(

                "organizationName",

                "Unknown"

            ),

            "issuer_country": issuer.get(

                "countryName",

                "Unknown"

            ),

            "valid_from": valid_from.strftime(

                "%d %B %Y"

            ),

            "valid_until": valid_until.strftime(

                "%d %B %Y"

            ),

            "days_left": days_left,

            "tls_version": tls_version,

            "certificate_version": certificate.get(

                "version",

                "Unknown"

            ),

            "serial_number": certificate.get(

                "serialNumber",

                "Unavailable"

            ),

            "self_signed": "Yes" if self_signed else "No"

        }

    except ssl.SSLError:

        return {

            "status": "Invalid",

            "common_name": "Unavailable",

            "organization": "Unavailable",

            "issuer": "Unavailable",

            "issuer_country": "Unavailable",

            "valid_from": "Unavailable",

            "valid_until": "Unavailable",

            "days_left": "Unavailable",

            "tls_version": "Unavailable",

            "certificate_version": "Unavailable",

            "serial_number": "Unavailable",

            "self_signed": "Unknown"

        }

    except socket.timeout:

        return {

            "status": "Timeout",

            "common_name": "Unavailable",

            "organization": "Unavailable",

            "issuer": "Unavailable",

            "issuer_country": "Unavailable",

            "valid_from": "Unavailable",

            "valid_until": "Unavailable",

            "days_left": "Unavailable",

            "tls_version": "Unavailable",

            "certificate_version": "Unavailable",

            "serial_number": "Unavailable",

            "self_signed": "Unknown"

        }

    except Exception:

        return {

            "status": "Unavailable",

            "common_name": "Unavailable",

            "organization": "Unavailable",

            "issuer": "Unavailable",

            "issuer_country": "Unavailable",

            "valid_from": "Unavailable",

            "valid_until": "Unavailable",

            "days_left": "Unavailable",

            "tls_version": "Unavailable",

            "certificate_version": "Unavailable",

            "serial_number": "Unavailable",

            "self_signed": "Unknown"

        }