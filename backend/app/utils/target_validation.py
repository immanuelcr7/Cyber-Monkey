import re
import ipaddress
from urllib.parse import urlparse

# Domain regex (supports standard subdomains and main domains up to 63 char labels)
DOMAIN_REGEX = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

def validate_domain(value: str) -> bool:
    if not value or len(value) > 255:
        return False
    return bool(DOMAIN_REGEX.match(value))

def validate_ip(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def validate_url(value: str) -> bool:
    if not value:
        return False
    try:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False
        
        hostname = parsed.hostname
        if not hostname:
            return False
            
        # The hostname must either be a valid domain or a valid IP
        return validate_domain(hostname) or validate_ip(hostname)
    except Exception:
        return False
