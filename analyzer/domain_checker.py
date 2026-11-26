"""DNS/HTTPS existence checks and evidence-ranked alternative suggestions.

This module only contacts the hostname explicitly submitted by a user or a
candidate derived from that hostname. Every request is checked for SSRF before
the connection and each redirect is revalidated. A Tranco rank is evidence of
popularity, not proof that a page is safe.
"""
from __future__ import annotations

import concurrent.futures
import csv
import ipaddress
import os
import re
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import dns.exception
import dns.resolver
import requests
import tldextract

from analyzer.page_analyzer import _ip_is_blocked, is_ssrf_risk

MAX_REDIRECTS = 3
MAX_BODY_BYTES = 512 * 1024
REQUEST_TIMEOUT = (2.5, 4.0)
USER_AGENT = "PhishGuardResearch/3.0 (+safe link verification; no scripts)"
COMMON_SUFFIXES = ("com", "org", "net", "in", "co", "io", "edu", "gov", "co.in", "ac.in")
TRUSTED_AGE_DAYS = 90
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
_TRANC0_CACHE: tuple[str, dict[str, int]] | None = None
_TRANC0_STEMS: dict[str, list[str]] | None = None
_TRANC0_STEMS_KEY: tuple[str, ...] | None = None
_TRANC0_LOCK = threading.Lock()
_WHOIS_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="whois-check")


def parse_user_input(value: str) -> dict[str, Any]:
    """Normalize a URL or bare hostname, rejecting malformed or unsafe targets."""
    raw = (value or "").strip()
    if not raw or len(raw) > 2048 or re.search(r"[\x00-\x1f\x7f]", raw):
        return {"valid": False, "message": "Enter a valid URL or domain (up to 2048 characters)."}
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"}:
        return {"valid": False, "message": "Only http and https addresses can be checked."}
    if parsed.username or parsed.password:
        return {"valid": False, "message": "Addresses containing embedded credentials cannot be checked."}
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return {"valid": False, "message": "The address does not contain a hostname."}
    try:
        host = host.encode("idna").decode("ascii")
        port = parsed.port
    except (UnicodeError, ValueError):
        return {"valid": False, "message": "The hostname or port is malformed."}
    if port not in (None, 80, 443):
        return {"valid": False, "message": "Only standard HTTP and HTTPS ports can be checked."}
    if is_ssrf_risk(host):
        # Keep an offline model prediction possible for an IP-shaped input, but
        # never resolve or fetch it from this server.
        return {"valid": True, "hostname": host, "registered_domain": None,
                "normalized_url": raw, "blocked": True,
                "message": "Network checks were blocked for a local or non-public target."}
    try:
        ipaddress.ip_address(host)
        ip_literal = True
    except ValueError:
        ip_literal = False
    ext = _EXTRACTOR(host)
    registered = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else None
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority += f":{port}"
    origin = urlunparse((parsed.scheme, authority, parsed.path or "/", parsed.params, parsed.query, ""))
    return {"valid": True, "hostname": host, "registered_domain": registered,
            "normalized_url": origin, "blocked": False, "ip_literal": ip_literal}


def resolve_host(hostname: str) -> dict[str, Any]:
    """Resolve common DNS record types and reject any private answer."""
    if is_ssrf_risk(hostname):
        return {"resolves": False, "blocked": True, "records": {}, "addresses": [],
                "error": "Local and non-public hosts are not looked up."}
    try:
        literal = ipaddress.ip_address(hostname)
        return {"resolves": True, "blocked": False, "records": {},
                "addresses": [str(literal)], "error": None, "ip_literal": True}
    except ValueError:
        pass
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 1.2
    resolver.lifetime = 2.5
    records: dict[str, list[str]] = {}
    addresses: set[str] = set()
    errors: list[str] = []
    for record_type in ("A", "AAAA", "CNAME", "NS"):
        try:
            answers = resolver.resolve(hostname, record_type, lifetime=2.5, search=False)
            records[record_type] = [answer.to_text().rstrip(".") for answer in answers]
            if record_type in {"A", "AAAA"}:
                addresses.update(records[record_type])
        except dns.resolver.NXDOMAIN:
            return {"resolves": False, "blocked": False, "records": {}, "addresses": [],
                    "error": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            continue
        except (dns.exception.DNSException, OSError) as exc:
            errors.append(type(exc).__name__)
    if not records and not addresses:
        return {"resolves": False, "blocked": False, "records": {}, "addresses": [],
                "error": ", ".join(sorted(set(errors))) or "No DNS records found."}
    for address in addresses:
        try:
            if _ip_is_blocked(ipaddress.ip_address(address)):
                return {"resolves": False, "blocked": True, "records": records,
                        "addresses": sorted(addresses),
                        "error": "The hostname resolves to a non-public address."}
        except ValueError:
            return {"resolves": False, "blocked": True, "records": records,
                    "addresses": sorted(addresses), "error": "DNS returned an invalid address."}
    return {"resolves": True, "blocked": False, "records": records,
            "addresses": sorted(addresses), "error": None}


def _checked_request(url: str, max_redirects: int = MAX_REDIRECTS,
                    max_bytes: int = MAX_BODY_BYTES) -> dict[str, Any]:
    """Fetch a small HTTP response, validating scheme, DNS and every redirect."""
    current = url
    session = requests.Session()
    session.trust_env = False
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"}
    try:
        for hop in range(max_redirects + 1):
            parsed = urlparse(current)
            host = (parsed.hostname or "").lower()
            if parsed.scheme not in {"http", "https"} or not host or is_ssrf_risk(host):
                return {"reachable": False, "blocked": True, "error": "Unsafe URL or redirect was blocked.",
                        "url": current, "redirects": hop, "tls_valid": False, "status_code": None,
                        "content_type": "", "body": ""}
            dns_result = resolve_host(host)
            if not dns_result["resolves"]:
                return {"reachable": False, "blocked": dns_result["blocked"],
                        "error": dns_result["error"] or "Hostname does not resolve.", "url": current,
                        "redirects": hop, "tls_valid": False, "status_code": None,
                        "content_type": "", "body": ""}
            try:
                response = session.get(current, headers=headers, timeout=REQUEST_TIMEOUT,
                                       allow_redirects=False, stream=True, verify=True)
            except requests.exceptions.SSLError as exc:
                return {"reachable": False, "blocked": False, "error": "TLS certificate validation failed.",
                        "url": current, "redirects": hop, "tls_valid": False, "status_code": None,
                        "content_type": "", "body": "", "exception": type(exc).__name__}
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                response.close()
                if not location or hop >= max_redirects:
                    return {"reachable": False, "blocked": False, "error": "Too many or malformed redirects.",
                            "url": current, "redirects": hop + 1, "tls_valid": parsed.scheme == "https",
                            "status_code": None, "content_type": "", "body": ""}
                current = urljoin(current, location)
                continue
            content_type = response.headers.get("Content-Type", "")
            body = bytearray()
            if content_type.lower().startswith("text/") or "application/xhtml" in content_type.lower() or not content_type:
                try:
                    for chunk in response.iter_content(chunk_size=16 * 1024):
                        if not chunk:
                            continue
                        body.extend(chunk[:max_bytes - len(body)])
                        if len(body) >= max_bytes:
                            break
                finally:
                    response.close()
            else:
                response.close()
            return {"reachable": True, "blocked": False, "error": None, "url": current,
                    "redirects": hop, "tls_valid": parsed.scheme == "https",
                    "status_code": response.status_code, "content_type": content_type,
                    "body": bytes(body).decode(response.encoding or "utf-8", errors="replace")}
        return {"reachable": False, "blocked": False, "error": "Too many redirects.", "url": current,
                "redirects": max_redirects, "tls_valid": False, "status_code": None,
                "content_type": "", "body": ""}
    except requests.exceptions.Timeout:
        return {"reachable": False, "blocked": False, "error": "The website timed out.",
                "url": current, "redirects": 0, "tls_valid": False, "status_code": None,
                "content_type": "", "body": ""}
    except requests.exceptions.RequestException as exc:
        return {"reachable": False, "blocked": False, "error": "The website could not be reached.",
                "url": current, "redirects": 0, "tls_valid": False, "status_code": None,
                "content_type": "", "body": "", "exception": type(exc).__name__}
    finally:
        session.close()


def _tranco_path() -> Path:
    configured = os.environ.get("TRANCO_CSV_PATH")
    return Path(configured) if configured else Path(__file__).resolve().parents[1] / "data" / "tranco.csv"


def load_tranco_ranks() -> dict[str, int]:
    """Load a local Tranco CSV with rank,domain columns; do not download data."""
    global _TRANC0_CACHE, _TRANC0_STEMS
    path = _tranco_path()
    try:
        stamp = str(path.resolve()) + (f":{path.stat().st_mtime_ns}" if path.exists() else ":missing")
    except OSError:
        stamp = str(path) + ":unavailable"
    with _TRANC0_LOCK:
        if _TRANC0_CACHE and _TRANC0_CACHE[0] == stamp:
            return _TRANC0_CACHE[1]
        _TRANC0_STEMS = None
        ranks: dict[str, int] = {}
        if path.exists():
            try:
                with path.open("r", encoding="utf-8-sig", newline="") as handle:
                    for row in csv.reader(handle):
                        if len(row) < 2:
                            continue
                        try:
                            rank = int(row[0].strip())
                        except ValueError:
                            continue
                        domain = row[1].strip().lower().rstrip(".")
                        if domain:
                            ranks[domain] = rank
            except OSError:
                ranks = {}
        _TRANC0_CACHE = (stamp, ranks)
        return ranks


def domain_age_days(domain: str) -> int | None:
    """Return age in days from WHOIS when available; timeout/failure is unknown."""
    try:
        import whois
    except ImportError:
        return None
    future = _WHOIS_POOL.submit(whois.whois, domain)
    try:
        record = future.result(timeout=2.5)
    except Exception:
        future.cancel()
        return None
    created = getattr(record, "creation_date", None)
    if isinstance(created, list):
        created = min((date for date in created if date), default=None)
    if not created:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).days)


def _evidence(domain: str, http: dict[str, Any]) -> dict[str, Any]:
    rank = load_tranco_ranks().get(domain)
    final_host = (urlparse(http.get("url", "")).hostname or "").lower()
    final_ext = _EXTRACTOR(final_host) if final_host else None
    final_registered = (f"{final_ext.domain}.{final_ext.suffix}"
                        if final_ext and final_ext.domain and final_ext.suffix else None)
    same_registered_domain = final_registered == domain
    tls_ok = bool(http.get("reachable") and http.get("tls_valid") and same_registered_domain)
    age = domain_age_days(domain) if rank is not None and tls_ok else None
    rank_ok = rank is not None
    age_ok = age is None or age >= TRUSTED_AGE_DAYS
    verified = rank_ok and tls_ok and age_ok
    reasons = []
    if rank is not None:
        reasons.append(f"Tranco rank #{rank} in the configured local list")
    else:
        reasons.append("No matching Tranco rank was found in the configured local list")
    reasons.append("HTTPS certificate validated" if tls_ok else "HTTPS reachability or certificate validation failed")
    if age is not None:
        reasons.append(f"WHOIS registration age: {age} days")
        if age < TRUSTED_AGE_DAYS:
            reasons.append(f"Domain is newer than the {TRUSTED_AGE_DAYS}-day evidence threshold")
    confidence = "high" if verified and rank is not None and rank <= 100_000 else (
        "medium" if tls_ok and rank_ok else "low")
    return {"verified_genuine": verified, "confidence": confidence, "tranco_rank": rank,
            "domain_age_days": age, "same_registered_domain": same_registered_domain,
            "reasons": reasons,
            "note": "These signals are evidence of legitimacy, not proof that every page is safe."}


def _candidate_names(hostname: str) -> list[str]:
    ext = _EXTRACTOR(hostname)
    stem = ext.domain or hostname
    variants = [stem]
    no_hyphen = stem.replace("-", "")
    if no_hyphen and no_hyphen != stem:
        variants.append(no_hyphen)
    candidates: list[str] = []
    for variant in variants:
        for suffix in COMMON_SUFFIXES:
            candidate = f"{variant}.{suffix}"
            if candidate != hostname and candidate not in candidates:
                candidates.append(candidate)
    # Try both apex and common www host forms for the highest-priority suffixes.
    www_variants = [f"www.{stem}.{suffix}" for stem in variants for suffix in COMMON_SUFFIXES[:4]]
    candidates = candidates[:4] + [candidate for candidate in www_variants
                                    if candidate != hostname and candidate not in candidates[:4]] + candidates[4:]

    # Use the local Tranco list as the reference set for near-miss brand names.
    ranks = load_tranco_ranks()
    fuzzy_candidates: list[str] = []
    if ranks:
        stems = _tranco_stems()
        try:
            from rapidfuzz import process
            from rapidfuzz.distance import Levenshtein
            matches = process.extract(stem, list(stems), scorer=Levenshtein.distance,
                                      limit=10, score_cutoff=2)
            near_stems = [name for name, distance, _ in matches if name != stem and distance <= 2]
        except ImportError:
            near_stems = [name for name in stems if name != stem and _edit_distance(stem, name) <= 2]
            near_stems.sort(key=lambda name: _edit_distance(stem, name))
            near_stems = near_stems[:10]
        for close_stem in near_stems:
            fuzzy_candidates.extend(sorted(stems[close_stem], key=lambda d: ranks[d])[:2])
    prioritized = candidates[:4] + [c for c in fuzzy_candidates if c not in candidates[:4]] + candidates[4:]
    return prioritized[:16]


def _tranco_stems() -> dict[str, list[str]]:
    """Build a cached index of registered labels from the local Tranco list."""
    global _TRANC0_STEMS, _TRANC0_STEMS_KEY
    ranks = load_tranco_ranks()
    key = tuple(ranks)
    if _TRANC0_STEMS is None or key != _TRANC0_STEMS_KEY:
        stems: dict[str, list[str]] = {}
        for domain in ranks:
            parsed = _EXTRACTOR(domain)
            if parsed.domain:
                stems.setdefault(parsed.domain, []).append(domain)
        _TRANC0_STEMS = stems
        _TRANC0_STEMS_KEY = key
    return _TRANC0_STEMS


def _edit_distance(left: str, right: str) -> int:
    """Small fallback Levenshtein implementation for optional-dependency setups."""
    previous = list(range(len(right) + 1))
    for row, left_char in enumerate(left, start=1):
        current = [row]
        for column, right_char in enumerate(right, start=1):
            current.append(min(current[-1] + 1, previous[column] + 1,
                               previous[column - 1] + (left_char != right_char)))
        previous = current
    return previous[-1]


def suggest_alternatives(hostname: str) -> list[dict[str, Any]]:
    """Return only candidates that resolve, serve HTTPS, and pass evidence checks."""
    suggestions = []
    seen_domains: set[str] = set()
    ranks = load_tranco_ranks()
    for candidate in _candidate_names(hostname):
        parsed = _EXTRACTOR(candidate)
        registered = f"{parsed.domain}.{parsed.suffix}" if parsed.domain and parsed.suffix else candidate
        if registered not in ranks or registered in seen_domains:
            continue
        dns_result = resolve_host(candidate)
        if not dns_result["resolves"] or dns_result["blocked"]:
            continue
        http = _checked_request(f"https://{candidate}/")
        evidence = _evidence(registered, http)
        if not (http.get("reachable") and http.get("tls_valid") and evidence["verified_genuine"]):
            continue
        seen_domains.add(registered)
        suggestions.append({"url": http["url"], "domain": registered, "rank": evidence["tranco_rank"],
                            "confidence": evidence["confidence"], "verified_genuine": True,
                            "reason": "; ".join(evidence["reasons"]),
                            "note": evidence["note"]})
    suggestions.sort(key=lambda item: (item["rank"] is None, item["rank"] or 10**9))
    return suggestions[:5]


def check_domain(value: str) -> dict[str, Any]:
    """Check DNS and HTTP(S) before a caller decides whether to run the ML model."""
    parsed = parse_user_input(value)
    if not parsed["valid"]:
        return {"status": "invalid", "exists": False, "message": parsed["message"],
                "hostname": None, "registered_domain": None, "dns": None, "http": None,
                "legitimacy": None, "suggestions": []}
    if parsed.get("blocked"):
        return {"status": "blocked", "exists": True, "message": parsed["message"],
                "hostname": parsed["hostname"], "registered_domain": None, "dns": None,
                "http": None, "legitimacy": None, "suggestions": []}
    host = parsed["hostname"]
    registered = parsed["registered_domain"]
    if parsed.get("ip_literal"):
        dns_result = {"resolves": True, "blocked": False, "records": {},
                      "addresses": [host], "error": None, "ip_literal": True}
    else:
        dns_result = resolve_host(host)
    if not dns_result["resolves"]:
        transient_dns_failure = dns_result.get("error") not in {"NXDOMAIN", "No DNS records found."}
        suggestions = [] if transient_dns_failure else suggest_alternatives(host)
        if suggestions:
            suggestion_message = "Only alternatives that passed DNS, HTTPS/TLS, Tranco, and available WHOIS evidence are shown."
        elif transient_dns_failure:
            suggestion_message = "No alternatives were checked because the DNS resolver did not return a reliable answer. Try again later."
        elif not load_tranco_ranks():
            suggestion_message = "No verified alternative is available. Configure TRANCO_CSV_PATH or add data/tranco.csv to enable popularity checks."
        else:
            suggestion_message = "No candidate passed the DNS, HTTPS/TLS, popularity, and available domain-age checks."
        status = "dns_unavailable" if transient_dns_failure else "does_not_resolve"
        message = (f"DNS lookup for {host} could not be completed, so phishing prediction was skipped."
                   if transient_dns_failure else
                   f"{host} does not resolve in DNS, so phishing prediction was skipped.")
        return {"status": status, "exists": False,
                "message": message,
                "hostname": host, "registered_domain": registered, "dns": dns_result,
                "http": None, "legitimacy": None, "suggestions": suggestions,
                "suggestions_message": suggestion_message}
    http = _checked_request(parsed["normalized_url"])
    # A domain may exist without HTTPS. Check plain HTTP only as a reachability
    # fallback; it can never satisfy the valid-TLS legitimacy requirement.
    if (not http.get("reachable") and not http.get("blocked")
            and value.strip().rstrip("/").lower() == host):
        http_fallback = _checked_request(f"http://{host}/")
        if http_fallback.get("reachable"):
            http = http_fallback
    evidence = _evidence(registered, http) if registered else None
    # If the submitted domain exists, also look for a close Tranco-listed domain
    # only when the label is a likely typo. The suggestion is still gated by all checks.
    suggestions = []
    stem = _EXTRACTOR(host).domain or ""
    ranks = load_tranco_ranks()
    near_tranco_brand = False
    if stem and ranks:
        known_stems = list(_tranco_stems())
        try:
            from rapidfuzz import process
            from rapidfuzz.distance import Levenshtein
            matches = process.extract(stem, known_stems, scorer=Levenshtein.distance,
                                      limit=8, score_cutoff=2)
            near_tranco_brand = any(name != stem and distance <= 2
                                    for name, distance, _ in matches)
        except ImportError:
            near_tranco_brand = any(name != stem and
                                    _edit_distance(stem, name) <= 2
                                    for name in known_stems)
    if stem and ranks and (not (evidence and evidence.get("verified_genuine")) or near_tranco_brand):
        suggestions = suggest_alternatives(host)
    if http.get("reachable"):
        message = f"{registered or host} resolves in DNS and responded with HTTP {http['status_code']}."
    else:
        message = f"{registered or host} resolves in DNS, but the website could not be reached: {http.get('error')}."
    return {"status": "exists", "exists": True, "message": message, "hostname": host,
            "registered_domain": registered, "dns": dns_result, "http": http,
            "legitimacy": evidence, "suggestions": suggestions}

