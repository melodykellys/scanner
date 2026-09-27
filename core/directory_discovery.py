from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from core.http_client import DEFAULT_TIMEOUT, create_session

COMMON_PATHS = [
    "/admin",
    "/login",
    "/dashboard",
    "/api",
    "/api/v1",
    "/graphql",
    "/.git",
    "/.env",
    "/backup",
    "/backup.zip",
    "/config",
    "/wp-admin",
    "/phpmyadmin",
    "/robots.txt",
    "/sitemap.xml",
    "/console",
    "/manage",
    "/debug",
    "/admin/login",
    "/uploads",
]
MAX_PATHS = 20
REQUEST_TIMEOUT = DEFAULT_TIMEOUT



def _normalize_target(target_input: str) -> str:
    value = target_input.strip()
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    parsed = urlparse(value)
    return f"{parsed.scheme}://{parsed.netloc}"

def _response_signature(response: requests.Response) -> tuple:
    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    body_hash = sha256(response.content[:200_000]).hexdigest()
    return response.status_code, content_type, body_hash


def _probe_path(session: requests.Session, base_url: str, path: str, baseline: Optional[tuple], baseline_verified: bool) -> Optional[Dict[str, Any]]:
    full_url = base_url.rstrip("/") + "/" + path.lstrip("/")
    try:
        response = session.get(full_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
    except requests.RequestException:
        return None

    if response.status_code not in (200, 301, 302, 401, 403, 405):
        return None        

    response_signature = _response_signature(response)
    if baseline and response_signature == baseline:
        return None

    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    file_like_path = path.lower().endswith((".zip", ".env", ".git", ".sql", ".bak", ".old"))
    generic_html_response = response.status_code == 200 and file_like_path and content_type == "text/html"
    if generic_html_response:
        category = "generic HTML response"
        confidence = "unverified"
    elif response.status_code == 200:
        confidence = "likely" if baseline_verified else "possible"
        category = "reachable endpoint"
    elif response.status_code in (401, 403):
        confidence = "possible" if baseline_verified else "unverified"
        category = "access-controlled endpoint"
    elif response.status_code == 405:
        confidence = "possible" if baseline_verified else "unverified"
        category = "method-restricted endpoint"
    else:
        confidence = "possible" if baseline_verified else "unverified"
        category = "redirect"

    return {
        "path": path,
        "url": full_url,
        "status_code": response.status_code,
        "category": category,
        "confidence": confidence,
        "evidence": "Generic HTML was returned for a file-like path; content requires manual verification." if generic_html_response else "Response differs from the target's missing-path baseline." if baseline_verified else "Baseline unavailable; response requires manual verification.",
        "content_type": content_type,
        "location": response.headers.get("Location"),
    }


def discover_directory_paths(target_input: str) -> Dict[str, Any]:
    base_url = _normalize_target(target_input)

    session = create_session()
    baseline = None
    baseline_verified = False
    try:
        baseline_url = base_url.rstrip("/") + "/__signal_recon_missing__"
        baseline_response = session.get(baseline_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        baseline = _response_signature(baseline_response)
        baseline_verified = True
    except requests.RequestException:
        pass

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(lambda path: _probe_path(session, base_url, path, baseline, baseline_verified), COMMON_PATHS[:MAX_PATHS])
        found_paths: List[Dict[str, Any]] = [result for result in results if result]

    return {
        "status": "success" if baseline_verified else "partial",
        "base_url": base_url,
        "verification": "verified" if baseline_verified else "partial",
        "message": None if baseline_verified else "The missing-path baseline could not be verified; findings may include custom error pages.",
        "count": len(found_paths),
        "paths": found_paths,
    }
