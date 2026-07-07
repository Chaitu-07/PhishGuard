import socket
import ipaddress
from urllib.parse import urlparse

import tldextract


# =====================================================
# DNS Lookup
# =====================================================

def get_dns_info(url):

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname

        if hostname is None:

            raise ValueError("Invalid hostname")

        # -----------------------------------------
        # IPv4
        # -----------------------------------------

        try:

            ipv4 = socket.gethostbyname(hostname)

        except Exception:

            ipv4 = "Unavailable"

        # -----------------------------------------
        # IPv6
        # -----------------------------------------

        try:

            ipv6 = socket.getaddrinfo(

                hostname,

                None,

                socket.AF_INET6

            )[0][4][0]

        except Exception:

            ipv6 = "Unavailable"

        # -----------------------------------------
        # Reverse DNS
        # -----------------------------------------

        try:

            reverse_dns = socket.gethostbyaddr(ipv4)[0]

        except Exception:

            reverse_dns = "Unavailable"

        # -----------------------------------------
        # Domain Parts
        # -----------------------------------------

        extracted = tldextract.extract(hostname)

        subdomain = extracted.subdomain or "None"

        domain = extracted.domain

        tld = "." + extracted.suffix if extracted.suffix else "Unavailable"

        # -----------------------------------------
        # Protocol / Port
        # -----------------------------------------

        protocol = parsed.scheme.upper()

        if parsed.port:

            port = parsed.port

        else:

            port = 443 if protocol == "HTTPS" else 80

        # -----------------------------------------
        # IP Classification
        # -----------------------------------------

        ip_type = "Unavailable"

        if ipv4 != "Unavailable":

            try:

                ip_obj = ipaddress.ip_address(ipv4)

                if ip_obj.is_private:

                    ip_type = "Private"

                elif ip_obj.is_loopback:

                    ip_type = "Loopback"

                elif ip_obj.is_reserved:

                    ip_type = "Reserved"

                else:

                    ip_type = "Public"

            except Exception:

                ip_type = "Unknown"

        # -----------------------------------------
        # Query Parameters
        # -----------------------------------------

        if parsed.query:

            query_count = len(parsed.query.split("&"))

        else:

            query_count = 0

        # -----------------------------------------
        # Return
        # -----------------------------------------

        return {

            "hostname": hostname,

            "domain": domain,

            "subdomain": subdomain,

            "tld": tld,

            "protocol": protocol,

            "port": port,

            "ip": ipv4,

            "ipv6": ipv6,

            "ip_type": ip_type,

            "reverse_dns": reverse_dns,

            "path": parsed.path if parsed.path else "/",

            "query_count": query_count,

            "fragment": parsed.fragment if parsed.fragment else "None",

            "url_length": len(url)

        }

    except Exception:

        return {

            "hostname": "Unavailable",

            "domain": "Unavailable",

            "subdomain": "Unavailable",

            "tld": "Unavailable",

            "protocol": "Unavailable",

            "port": "Unavailable",

            "ip": "Unavailable",

            "ipv6": "Unavailable",

            "ip_type": "Unavailable",

            "reverse_dns": "Unavailable",

            "path": "Unavailable",

            "query_count": 0,

            "fragment": "Unavailable",

            "url_length": 0

        }