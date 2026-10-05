from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse


CONFIDENCE_SCORES = {
    "confirmed": 1.0,     
    "likely": 0.8,
    "possible": 0.5,
    "unverified": 0.1,
}


def _normalise_key(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.netloc.lower()}{parsed.path.rstrip('/') or '/'}"
    return value.lower().rstrip('/') or "/"


def _finding(kind: str, title: str, confidence: str, evidence: str, key: str) -> Dict[str, Any]:
    level = confidence if confidence in CONFIDENCE_SCORES else "unverified"
    return {
        "id": f"{kind}:{_normalise_key(key)}",
        "type": kind,
        "title": title,
        "confidence": level,
        "score": CONFIDENCE_SCORES[level],
        "evidence": evidence,
    }


def _iter_findings(results: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for item in results.get("directories", {}).get("paths", []):
        yield _finding("directory", item["path"], item.get("confidence", "unverified"), item.get("evidence", ""), item["url"])

    for item in results.get("subdomains", {}).get("subdomains", []):
        yield _finding("subdomain", item["hostname"], item.get("confidence", "unverified"), f"DNS: {item.get('status')}; HTTP verified: {item.get('http_verified', False)}", item["hostname"])

    js_api = results.get("js_api", {})
    for endpoint in js_api.get("endpoints", []):
        yield _finding("endpoint", endpoint, "possible", "Extracted from inspected HTML or same-origin JavaScript.", endpoint)
    for secret in js_api.get("possible_secrets", []):
        yield _finding("possible_secret", secret, js_api.get("possible_secret_confidence", "possible"), "Pattern matched in inspected client-side code; value is masked.", secret)

    for item in results.get("technology", {}).get("technologies", []):
        yield _finding("technology", item["name"], item.get("confidence", "possible"), item.get("evidence", ""), f"{item['category']}:{item['name']}")


def build_scan_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    unique: Dict[str, Dict[str, Any]] = {}
    for item in _iter_findings(results):
        existing = unique.get(item["id"])
        if existing is None or item["score"] > existing["score"]:
            unique[item["id"]] = item

    findings = sorted(unique.values(), key=lambda item: (-item["score"], item["type"], item["title"]))
    counts = {level: sum(item["confidence"] == level for item in findings) for level in CONFIDENCE_SCORES}
    return {
        "finding_count": len(findings),
        "confidence_counts": counts,
        "top_findings": findings[:20],
        "deduplicated": True,
    }