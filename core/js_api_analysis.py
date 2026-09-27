import re
from html.parser import HTMLParser
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

import requests
from core.http_client import DEFAULT_TIMEOUT, create_session


MAX_JS_FILES = 10                     
MAX_ENDPOINTS = 50
MAX_SECRET_FINDINGS = 20
MAX_ENDPOINT_LENGTH = 180
MAX_OPAQUE_SEGMENT_LENGTH = 80
PUBLIC_KEY_PATTERNS = [
    ("Google Maps browser key", r"\bAIza[0-9A-Za-z_-]{30,}\b"),
]
WAF_MARKERS = ("incapsula", "imperva", "cloudflare", "akamai", "captcha", "challenge")
SECRET_PATTERNS = [
    ("named credential", r"(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("private key block", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{40,5000}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]


class _ScriptLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        attributes = dict(attrs)
        source = attributes.get("src")
        if source and not source.startswith("data:"):
            self.links.append(source)


def _extract_js_links(html: str) -> List[str]:
    parser = _ScriptLinkParser()
    parser.feed(html)
    return sorted(set(parser.links))


def _extract_endpoints(html: str, allowed_host: str | None = None) -> List[str]:
    patterns = [
        r"https?://[A-Za-z0-9._:/?=&%\-]+",
        r"/(?:api|graphql|v[0-9]+|auth|oauth|login|users|admin)[A-Za-z0-9_/?=&%\-.]*",
    ]
    endpoints = set()
    for pattern in patterns:
        for match in re.findall(pattern, html, flags=re.IGNORECASE):
            path = match.split("#", 1)[0]
            path = re.sub(r"([?&](?:api[_-]?key|key)=)[^&]*", "", path, flags=re.IGNORECASE).rstrip("?&")
            parsed = urlparse(path)
            if parsed.scheme and parsed.netloc and allowed_host and parsed.netloc.lower() != allowed_host.lower():
                continue
            if len(path) > MAX_ENDPOINT_LENGTH or any(len(segment) > 120 for segment in parsed.path.split("/")):
                continue
            if _is_waf_artifact(path):
                continue
            if parsed.hostname and parsed.hostname.lower() in {"localhost", "www.w3.org"}:
                continue
            if path.lower().split("?", 1)[0].endswith((".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2")):
                continue
            if path.endswith("?key="):
                continue
            if "http" in path or path.startswith("/"):
                endpoints.add(path)
    return sorted(endpoints)[:MAX_ENDPOINTS]


def _is_waf_artifact(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in WAF_MARKERS):
        return True
    segments = urlparse(value).path.split("/")
    for segment in segments:
        if len(segment) < MAX_OPAQUE_SEGMENT_LENGTH:
            continue
        alphabet = set(segment)
        if len(alphabet) > 20 and re.fullmatch(r"[A-Za-z0-9_=-]+", segment):
            return True
    return False


def _extract_public_client_keys(text: str) -> List[Dict[str, str]]:
    findings = []
    for label, pattern in PUBLIC_KEY_PATTERNS:
        for match in re.finditer(pattern, text):
            value = match.group(0)
            findings.append({
                "type": "public_client_key",
                "name": label,
                "masked_value": f"{value[:4]}...{value[-4:]}",
                "classification": "Public browser key; exposure alone does not establish a vulnerability.",
            })
    return findings[:MAX_SECRET_FINDINGS]


def _extract_possible_secrets(text: str) -> List[str]:
    findings = []
    public_values = {
        match.group(0)
        for _label, pattern in PUBLIC_KEY_PATTERNS
        for match in re.finditer(pattern, text)
    }
    for label, pattern in SECRET_PATTERNS:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            value = match.group(1) if match.lastindex else match.group(0)
            if value in public_values or _is_waf_artifact(value):
                continue
            if len(value) > 8:
                findings.append(f"{label}: {value[:2]}...{value[-2:]}")
    return sorted(set(findings))[:MAX_SECRET_FINDINGS]


def analyze_js_and_api(target_input: str) -> Dict[str, Any]:
    value = target_input.strip()
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"

    parsed = urlparse(value)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    discovered_js = []
    endpoints = []
    secrets = []
    public_client_keys = []
    waf_artifacts = set()

    try:
        session = create_session()
        page = session.get(value, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        page.raise_for_status()
        page_text = page.text
        public_client_keys.extend(_extract_public_client_keys(page_text))
        waf_artifacts.update(match.group(0) for match in re.finditer(r"https?://[^\s'\"<>]+|/[^\s'\"<>]+", page_text) if _is_waf_artifact(match.group(0)))
        discovered_js = [
            link for link in _extract_js_links(page_text)
            if "_incapsula_resource" not in link.lower()
            and not _is_waf_artifact(link)
            and urlparse(urljoin(value, link)).netloc == parsed.netloc
        ]

        for js_url in discovered_js[:MAX_JS_FILES]:
            full_js_url = urljoin(value, js_url)
            if urlparse(full_js_url).netloc != parsed.netloc:
                continue
            try:
                js_response = session.get(full_js_url, timeout=DEFAULT_TIMEOUT)
                js_response.raise_for_status()
                if "javascript" not in js_response.headers.get("Content-Type", "").lower() and not full_js_url.lower().split("?")[0].endswith((".js", ".mjs")):
                    continue
                public_client_keys.extend(_extract_public_client_keys(js_response.text))
                waf_artifacts.update(match.group(0) for match in re.finditer(r"https?://[^\s'\"<>]+|/[^\s'\"<>]+", js_response.text) if _is_waf_artifact(match.group(0)))
                endpoints.extend(_extract_endpoints(js_response.text, parsed.netloc))
                secrets.extend(_extract_possible_secrets(js_response.text))
            except requests.RequestException:
                continue

        endpoints.extend(_extract_endpoints(page_text, parsed.netloc))
        secrets.extend(_extract_possible_secrets(page_text))

        return {
            "status": "success",
            "base_url": base_url,
            "javascript_files": discovered_js,
            "endpoints": sorted(set(endpoints))[:50],
            "possible_secrets": sorted(set(secrets))[:20],
            "public_client_keys": list({item["masked_value"]: item for item in public_client_keys}.values()),
            "waf_artifacts": sorted(waf_artifacts)[:20],
            "possible_secret_confidence": "possible" if secrets else None,
            "verification": "Static HTML and same-origin JavaScript inspected; endpoints were not authenticated or fully crawled.",
        }
    except requests.RequestException as exc:
        return {"status": "error", "base_url": base_url, "message": str(exc)}
