import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests
from core.http_client import DEFAULT_TIMEOUT, create_session


MAX_SUBDOMAINS = 100
HTTP_TIMEOUT = 5


def _get_hostname(target_input: str) -> str:
    value = target_input.strip()
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    hostname = (urlparse(value).hostname or "").lower().rstrip(".")
    return hostname[4:] if hostname.startswith("www.") else hostname


def _certificate_names(domain: str) -> List[str]:
    response = requests.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        timeout=10,
    )
    response.raise_for_status()

    names = set()
    for certificate in response.json():
        for raw_name in certificate.get("name_value", "").splitlines():
            name = raw_name.strip().lower().lstrip("*.").rstrip(".")
            if name and name != domain and name.endswith(f".{domain}"):
                names.add(name)

    return sorted(names)[:MAX_SUBDOMAINS]


def _resolve_name(name: str) -> Dict[str, Any]:
    try:
        addresses = sorted({result[4][0] for result in socket.getaddrinfo(name, None)})
        return {"hostname": name, "addresses": addresses, "status": "resolved"}
    except socket.gaierror:
        return {"hostname": name, "addresses": [], "status": "no_dns"}


def _probe_http(name: str) -> Dict[str, Any]:
    for scheme in ("https", "http"):
        try:
            response = create_session().get(f"{scheme}://{name}", timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            return {
                "http_status": response.status_code,
                "http_url": response.url,
                "http_verified": True,
            }
        except requests.RequestException:
            continue
    return {"http_status": None, "http_url": None, "http_verified": False}


def _verify_subdomain(name: str) -> Dict[str, Any]:
    result = _resolve_name(name)
    result.update(_probe_http(name))
    if result["status"] == "resolved" and result["http_verified"]:
        result["confidence"] = "likely"
    elif result["status"] == "resolved":
        result["confidence"] = "possible"
    else:
        result["confidence"] = "unverified"
    return result


def enumerate_subdomains(target_input: str) -> Dict[str, Any]:
    domain = _get_hostname(target_input)
    if not domain:
        return {"status": "error", "message": "A valid domain is required."}

    try:
        names = _certificate_names(domain)
        with ThreadPoolExecutor(max_workers=8) as executor:
            discovered = list(executor.map(_verify_subdomain, names))
        return {
            "status": "success",
            "domain": domain,
            "source": "Certificate Transparency logs + DNS resolution",
            "verification": "DNS and HTTP reachability checked",
            "count": len(discovered),
            "subdomains": discovered,
        }
    except (requests.RequestException, ValueError) as error:
        return {"status": "error", "domain": domain, "source_status": "unavailable", "message": str(error)}
