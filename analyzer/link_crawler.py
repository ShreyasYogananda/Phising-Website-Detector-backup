"""Depth-one, SSRF-safe internal subpage inspection for verified parent sites."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from analyzer.domain_checker import USER_AGENT, _checked_request, is_ssrf_risk
from models.explainer import RiskExplainer

KEY_PAGES = ("login", "signin", "sign-in", "signup", "register", "account", "payment",
             "checkout", "pay", "billing", "cart", "contact", "about", "support")
PAYMENT_HOSTS = ("stripe.com", "razorpay.com", "paypal.com", "adyen.com", "squareup.com")
MAX_LINKS = 30


def registered_domain(hostname: str) -> str | None:
    """Use the same public-suffix-aware parser as the URL feature extractor."""
    try:
        from analyzer.domain_checker import _EXTRACTOR
        ext = _EXTRACTOR((hostname or "").lower().rstrip("."))
        return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else None
    except Exception:
        return None


def _priority(url: str, anchor: str) -> tuple[int, str]:
    text = f"{url} {anchor}".lower()
    rank = next((index for index, term in enumerate(KEY_PAGES) if term in text), len(KEY_PAGES))
    return rank, url


def _robots_policy(origin: str) -> RobotFileParser | bool | None:
    """Read robots.txt safely; None means allowed by absence, False means fail closed."""
    robots_url = urljoin(origin, "/robots.txt")
    fetched = _checked_request(robots_url, max_bytes=128 * 1024)
    if not fetched.get("reachable"):
        if fetched.get("status_code") in {404, 410}:
            return None
        return False
    # A robots redirect to a different registered domain cannot authorize us to
    # crawl the original site's links, so stop instead of guessing the policy.
    origin_host = (urlparse(origin).hostname or "").lower()
    final_host = (urlparse(fetched.get("url", "")).hostname or "").lower()
    if registered_domain(origin_host) != registered_domain(final_host):
        return False
    if fetched.get("status_code", 200) >= 400:
        return None if fetched.get("status_code") in {404, 410} else False
    if not fetched.get("body"):
        return None
    parser = RobotFileParser()
    parser.set_url(robots_url)
    parser.parse(fetched["body"].splitlines())
    return parser


def _is_payment_host(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    return any(host == base or host.endswith("." + base) for base in PAYMENT_HOSTS)


def _red_flags(soup: BeautifulSoup, page_url: str) -> list[dict]:
    flags: list[dict] = []
    page_host = (urlparse(page_url).hostname or "").lower()
    page_registered = registered_domain(page_host)
    for form in soup.find_all("form"):
        action = urljoin(page_url, form.get("action") or page_url)
        form_host = (urlparse(action).hostname or "").lower()
        form_registered = registered_domain(form_host)
        fields = " ".join([form.get("id", ""), form.get("name", ""), form.get_text(" ", strip=True)[:250]]).lower()
        has_password = form.find("input", attrs={"type": re.compile(r"^password$", re.I)}) is not None
        sensitive = has_password or any(term in fields for term in ("login", "sign in", "password", "payment", "checkout"))
        if sensitive and form_registered != page_registered:
            flags.append({"code": "cross_domain_form", "severity": "high",
                          "detail": "A credential/payment form submits outside the page's registered domain."})
    for frame in soup.find_all("iframe"):
        style = (frame.get("style") or "").replace(" ", "").lower()
        hidden = (frame.has_attr("hidden") or frame.get("aria-hidden") == "true" or
                  "display:none" in style or "visibility:hidden" in style or
                  frame.get("width") == "0" or frame.get("height") == "0")
        if hidden:
            flags.append({"code": "hidden_iframe", "severity": "medium",
                          "detail": "The page contains an iframe hidden from the user."})
            break
    for script in soup.find_all("script"):
        source = script.get_text(" ", strip=True)
        if re.search(r"(?:window|document)\.location(?:\.href)?\s*=|location\.replace\s*\(|location\.assign\s*\(", source, re.I):
            flags.append({"code": "javascript_redirect", "severity": "medium",
                          "detail": "Inline JavaScript contains a client-side location redirect."})
            break
    if soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)}):
        flags.append({"code": "meta_refresh", "severity": "medium",
                      "detail": "The page contains a meta refresh redirect."})
    for anchor in soup.find_all("a", href=True):
        target = urljoin(page_url, anchor["href"])
        host = (urlparse(target).hostname or "").lower()
        try:
            ipaddress.ip_address(host.strip("[]"))
            flags.append({"code": "ip_based_link", "severity": "high",
                          "detail": "A page link points directly to an IP address."})
            break
        except ValueError:
            pass
        text = anchor.get_text(" ", strip=True).lower()
        match = re.search(r"(?:https?://)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})", text)
        if match and host and match.group(1).rstrip(".") not in host and host not in match.group(1).rstrip("."):
            flags.append({"code": "anchor_href_mismatch", "severity": "medium",
                          "detail": "A link's visible domain text does not match its destination host."})
            break
    return flags


def _inspect_subpage(url: str, parent_domain: str, parent_genuine: bool) -> dict:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    target_domain = registered_domain(host)
    if not target_domain or target_domain != parent_domain:
        return {"url": url, "final_url": None, "same_registered_domain": False,
                "https": parsed.scheme == "https", "tls_valid": False, "http_status": None,
                "reachable": False, "verdict": "Third-party",
                "reason": "This link leaves the parent's registered domain; external sites are not assumed genuine.",
                "red_flags": [], "ml_verdict": None, "risk_score": None}
    if is_ssrf_risk(host):
        return {"url": url, "final_url": None, "same_registered_domain": True,
                "https": parsed.scheme == "https", "tls_valid": False, "http_status": None,
                "reachable": False, "verdict": "Unreachable", "reason": "A private or local destination was blocked.",
                "red_flags": [], "ml_verdict": None, "risk_score": None}
    fetched = _checked_request(url)
    if not fetched.get("reachable"):
        return {"url": url, "final_url": fetched.get("url"), "same_registered_domain": True,
                "https": parsed.scheme == "https", "tls_valid": False, "http_status": fetched.get("status_code"),
                "reachable": False, "verdict": "Unreachable", "reason": fetched.get("error") or "The page could not be reached.",
                "red_flags": [], "ml_verdict": None, "risk_score": None}
    final_url = fetched["url"]
    final_host = (urlparse(final_url).hostname or "").lower()
    same_domain = registered_domain(final_host) == parent_domain
    try:
        prediction = RiskExplainer.analyze_url(url)
        ml_verdict = prediction["unified_verdict"]
        risk_score = prediction["hybrid_risk_score"]
    except Exception:
        ml_verdict, risk_score = "Unavailable", None
    soup = BeautifulSoup(fetched.get("body", ""), "html.parser")
    flags = _red_flags(soup, final_url)
    status = fetched.get("status_code")
    reasons = []
    if not same_domain:
        verdict = "Third-party"
        reasons.append("The page redirected to a different registered domain.")
    elif not fetched.get("tls_valid"):
        verdict = "Suspicious"
        reasons.append("HTTPS with a validated certificate was not confirmed.")
    elif status is None or status >= 400:
        verdict = "Suspicious"
        reasons.append(f"The server returned HTTP {status}.")
    elif any(flag["severity"] == "high" for flag in flags):
        verdict = "Phishing"
        reasons.extend(flag["detail"] for flag in flags)
    elif ml_verdict == "High risk":
        verdict = "Phishing"
        reasons.append("The existing hybrid URL detector classified this subpage as high risk.")
    elif flags or ml_verdict != "Likely safe":
        verdict = "Suspicious"
        reasons.extend(flag["detail"] for flag in flags)
        if ml_verdict not in {"Likely safe", "Unavailable"}:
            reasons.append(f"The existing hybrid URL detector said: {ml_verdict}.")
        elif ml_verdict == "Unavailable":
            reasons.append("The existing model result was unavailable.")
    elif not parent_genuine:
        verdict = "Suspicious"
        reasons.append("The parent site has not passed the legitimacy evidence checks.")
    else:
        verdict = "Genuine"
        reasons.append("Same registered domain, successful HTTPS, no detected page red flags, and low model risk.")
    return {"url": url, "final_url": final_url, "same_registered_domain": same_domain,
            "https": parsed.scheme == "https", "tls_valid": bool(fetched.get("tls_valid")),
            "http_status": status, "reachable": True, "verdict": verdict,
            "reason": " ".join(dict.fromkeys(reasons)), "red_flags": flags,
            "ml_verdict": ml_verdict, "risk_score": risk_score}


def inspect_subpages(parent_url: str, parent_registered_domain: str | None,
                     parent_genuine: bool, homepage_html: str | None = None) -> dict:
    """Crawl up to 30 depth-one links, honoring robots.txt and not following scripts."""
    if not parent_registered_domain or not parent_genuine:
        return {"enabled": False, "message": "Subpages are not marked genuine because the parent did not pass all legitimacy checks.",
                "verified_count": 0, "flagged_count": 0, "total_count": 0, "links": []}
    origin = urljoin(parent_url, "/")
    if homepage_html is None:
        fetched = _checked_request(origin)
        if not fetched.get("reachable"):
            return {"enabled": False, "message": "The parent page could not be fetched for subpage discovery.",
                    "verified_count": 0, "flagged_count": 0, "total_count": 0, "links": []}
        homepage_html = fetched.get("body", "")
    soup = BeautifulSoup(homepage_html or "", "html.parser")
    robots = _robots_policy(origin)
    if robots is False:
        return {"enabled": False, "message": "robots.txt could not be safely checked; subpage crawling was stopped.",
                "verified_count": 0, "flagged_count": 0, "total_count": 0, "links": []}
    internal: dict[str, str] = {}
    external: dict[str, str] = {}
    for anchor in soup.find_all("a", href=True):
        text = anchor.get_text(" ", strip=True)
        href = anchor.get("href", "").strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        absolute, _fragment = urldefrag(urljoin(origin, href))
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        host = parsed.hostname.lower()
        if is_ssrf_risk(host):
            continue
        registered = registered_domain(host)
        if registered == parent_registered_domain:
            internal.setdefault(absolute, text)
        elif _is_payment_host(host) or any(term in f"{absolute} {text}".lower() for term in KEY_PAGES):
            external.setdefault(absolute, text)
    selected_internal = sorted(internal.items(), key=lambda pair: _priority(pair[0], pair[1]))[:MAX_LINKS]
    results = []
    for url, _text in selected_internal:
        if robots and not robots.can_fetch(USER_AGENT, url):
            results.append({"url": url, "final_url": None, "same_registered_domain": True,
                            "https": url.startswith("https://"), "tls_valid": False, "http_status": None,
                            "reachable": False, "verdict": "Unreachable", "reason": "robots.txt disallows automated inspection.",
                            "red_flags": [], "ml_verdict": None, "risk_score": None})
        else:
            results.append(_inspect_subpage(url, parent_registered_domain, parent_genuine))
    slots = max(0, MAX_LINKS - len(results))
    for url, text in sorted(external.items(), key=lambda pair: _priority(pair[0], pair[1]))[:slots]:
        results.append({"url": url, "final_url": None, "same_registered_domain": False,
                        "https": url.startswith("https://"), "tls_valid": None, "http_status": None,
                        "reachable": None, "verdict": "Third-party",
                        "reason": "External link (including payment gateways) is listed separately and is not assumed genuine.",
                        "red_flags": [], "ml_verdict": None, "risk_score": None})
    verified = sum(result["verdict"] == "Genuine" for result in results)
    flagged = len(results) - verified
    return {"enabled": True,
            "message": f"{verified}/{len(results)} discovered links verified genuine; {flagged} flagged or external.",
            "verified_count": verified, "flagged_count": flagged, "total_count": len(results),
            "links": results}

