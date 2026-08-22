import time
from typing import List, Dict, Any, Tuple, Optional
import dns.resolver
import dns.exception
import dns.query
import dns.message

# Cache verified working nameservers list
_working_nameservers_cache: Optional[List[str]] = None

def get_configured_resolver(timeout: Optional[float] = None) -> dns.resolver.Resolver:
    """
    Constructs a dns.resolver.Resolver using environment Settings.
    """
    resolver = dns.resolver.Resolver()
    
    from app.core.config import settings
    
    # Load timeout
    if timeout is None:
        timeout = getattr(settings, "DNS_TIMEOUT", 2.0)
    resolver.timeout = timeout
    
    # Load explicitly configured nameservers
    env_resolver = getattr(settings, "DNS_RESOLVER", None)
    if env_resolver:
        nameservers = [ip.strip() for ip in env_resolver.replace(",", " ").split() if ip.strip()]
        if nameservers:
            resolver.nameservers = nameservers
            
    resolver.lifetime = timeout * len(resolver.nameservers)
    return resolver

def get_working_resolver(timeout: Optional[float] = None) -> dns.resolver.Resolver:
    """
    Returns a resolver containing only working nameservers from the configured list.
    Saves results to cache to avoid re-testing on every query.
    """
    global _working_nameservers_cache
    resolver = get_configured_resolver(timeout)
    
    # If cache is populated, use cached nameservers directly
    if _working_nameservers_cache is not None:
        if _working_nameservers_cache:
            resolver.nameservers = _working_nameservers_cache
            resolver.lifetime = resolver.timeout * len(resolver.nameservers)
            return resolver
            
    # Test configured nameservers to filter out unreachable ones (like 10.1.14.1)
    working_ips = []
    # Fast test timeout (0.5s) to check responsiveness
    test_timeout = 0.5
    
    # Basic query for a root server or well-known domain to check if nameserver responds
    q = dns.message.make_query("example.com", "A")
    for ns in resolver.nameservers:
        try:
            dns.query.udp(q, ns, timeout=test_timeout)
            working_ips.append(ns)
        except Exception:
            # Nameserver timed out or refused connection
            continue
            
    if working_ips:
        _working_nameservers_cache = working_ips
        resolver.nameservers = working_ips
    else:
        # If no nameservers are responsive, do not override/empty the list
        # (allows query to attempt standard resolution and raise appropriate timeout/error)
        pass
        
    resolver.lifetime = resolver.timeout * len(resolver.nameservers)
    return resolver

def check_dns_availability() -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Checks if DNS resolution capability is available on the backend machine.
    Performs a real lightweight DNS lookup to verify connectivity.
    Returns (available, resolver_ips, status_detail).
    """
    global _working_nameservers_cache
    # Clear cache to perform a fresh connectivity check
    _working_nameservers_cache = None
    
    try:
        resolver = get_working_resolver()
        resolver_ips = ", ".join(resolver.nameservers)
    except Exception as e:
        return False, None, f"Resolver initialization failed: {str(e)}"
        
    if not resolver.nameservers:
        return False, None, "No DNS nameservers are configured or available."
        
    # Perform a test query using the working resolver
    test_domains = ["example.com", "google.com"]
    success = False
    error_msg = None
    
    for domain in test_domains:
        try:
            resolver.resolve(domain, "A")
            success = True
            break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # Domain exists but no A record, query completed successfully
            success = True
            break
        except Exception as e:
            error_msg = str(e)
            
    if success:
        return True, resolver_ips, "DNS resolution is fully functional."
    else:
        return False, resolver_ips, f"DNS query failed: {error_msg or 'Unreachable nameservers'}"

def execute_dns_scan(domain: str, timeout: Optional[float] = None) -> Dict[str, Any]:
    """
    Performs authorized DNS record enumeration for a domain target.
    Returns a dict with: status, error_output, duration, records.
    Supported types: A, AAAA, MX, NS, CNAME, TXT, SOA.
    """
    start_time = time.time()
    records = []
    record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA"]
    
    try:
        resolver = get_working_resolver(timeout)
    except Exception as e:
        return {
            "status": "failed",
            "error_output": f"Failed to initialize DNS resolver: {str(e)}",
            "duration": 0.0,
            "records": []
        }
    
    # Flags to keep track of any overall failure
    timeout_encountered = False
    resolver_failure_encountered = False
    
    try:
        # First verify if the domain itself exists using A or SOA
        domain_exists = False
        try:
            resolver.resolve(domain, "A")
            domain_exists = True
        except dns.resolver.NXDOMAIN:
            # Try SOA as fallback in case it's a sub-delegation or no A record
            try:
                resolver.resolve(domain, "SOA")
                domain_exists = True
            except dns.resolver.NXDOMAIN:
                domain_exists = False
            except Exception:
                domain_exists = True
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            domain_exists = True
        except Exception:
            domain_exists = True
            
        if not domain_exists:
            duration = round(time.time() - start_time, 2)
            return {
                "status": "failed",
                "error_output": f"Domain {domain} not found (NXDOMAIN).",
                "duration": duration,
                "records": []
            }

        # Perform individual queries
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    val = ""
                    if rtype == "MX":
                        val = f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
                    elif rtype in ["CNAME", "NS"]:
                        val = rdata.target.to_text().rstrip('.')
                    elif rtype == "TXT":
                        val = b" ".join(rdata.strings).decode('utf-8', errors='ignore')
                    elif rtype == "SOA":
                        val = rdata.to_text().rstrip('.')
                    else:
                        val = rdata.to_text().rstrip('.')
                    
                    records.append({
                        "record_type": rtype,
                        "name": domain,
                        "value": val,
                        "ttl": answers.ttl
                    })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # No records of this type, or NXDOMAIN on specific query (normal)
                continue
            except dns.resolver.NoNameservers:
                resolver_failure_encountered = True
                break
            except dns.exception.Timeout:
                timeout_encountered = True
                break
            except Exception:
                # Skip other individual errors and continue
                continue

        duration = round(time.time() - start_time, 2)

        if timeout_encountered:
            return {
                "status": "failed",
                "error_output": "DNS resolution query timed out.",
                "duration": duration,
                "records": []
            }

        if resolver_failure_encountered:
            return {
                "status": "failed",
                "error_output": "DNS resolver failure (no name servers could be reached).",
                "duration": duration,
                "records": []
            }

        return {
            "status": "completed",
            "error_output": None if records else "No records found.",
            "duration": duration,
            "records": records
        }

    except Exception as e:
        duration = round(time.time() - start_time, 2)
        return {
            "status": "failed",
            "error_output": f"DNS resolution failed: {str(e)}",
            "duration": duration,
            "records": []
        }
