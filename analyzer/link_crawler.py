"""Depth-one, SSRF-safe internal subpage inspection for verified parent sites."""
from __future__ import annotations

import ipaddress
import re
import time
from xml.etree import ElementTree as ET
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
    fetched = _checked_request(robots_url, max_redirects=0, max_bytes=128 * 1024)
    if not fetched.get("reachable") or fetched.get("status_code") != 200 or not fetched.get("body"):
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
    fetched = _checked_request(url, max_redirects=0)
    if not fetched.get("reachable"):
        return {"url": url, "final_url": fetched.get("url"), "same_registered_domain": True,
                "https": parsed.scheme == "https", "tls_valid": False, "http_status": fetched.get("status_code"),
                "reachable": False, "verdict": "Unreachable", "reason": fetched.get("error") or "The page could not be reached.",
                "red_flags": [], "ml_verdict": None, "risk_score": None}
    final_url = fetched.get("location") or fetched["url"]
    final_host = (urlparse(final_url).hostname or "").lower()
    same_domain = registered_domain(final_host) == parent_domain
    try:
        prediction = RiskExplainer.analyze_url(final_url)
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
    elif fetched.get("redirects"):
        verdict = "Unverified"
        reasons.append("Redirect response. Direct page content was unavailable.")
    elif not fetched.get("body") or "html" not in fetched.get("content_type", "").lower():
        verdict = "Suspicious"
        reasons.append("No HTML was available to inspect for page-level risks.")
    elif any(flag["severity"] == "high" for flag in flags):
        verdict = "Phishing"
        reasons.extend(flag["detail"] for flag in flags)
    elif ml_verdict == "High risk":
        verdict = "Phishing"
        reasons.append("The existing hybrid URL detector classified this subpage as high risk.")
    elif not parent_genuine or fetched.get("redirects") or not 200 <= status < 300 or ml_verdict == "Unavailable":
        verdict = "Unverified"
        reasons.append("Inheritance requires a verified parent, direct 2xx response and available detector result.")
    else:
        verdict = "Genuine"
        reasons.append("Inherited from verified parent.")
    reasons.extend(flag["detail"] for flag in flags)
    if ml_verdict == "Suspicious":
        reasons.append("Warning: hybrid detector rated this address Suspicious.")
    return {"url": url, "final_url": final_url, "same_registered_domain": same_domain,
            "https": parsed.scheme == "https", "tls_valid": bool(fetched.get("tls_valid")),
            "http_status": status, "reachable": True, "verdict": verdict,
            "reason": " ".join(dict.fromkeys(reasons)), "red_flags": flags,
            "ml_verdict": ml_verdict, "risk_score": risk_score,
            "about_text": " ".join(p.get_text(" ", strip=True) for p in soup.select("p")[:8])[:2500]
            if same_domain and status == 200 and "about" in parsed.path.lower() else ""}


def inspect_subpages(parent_url: str, parent_registered_domain: str | None,
                     parent_genuine: bool, homepage_html: str | None = None) -> dict:
    """Crawl up to 30 depth-one links, honoring robots.txt and not following scripts."""
    origin = urljoin(parent_url, "/")
    if homepage_html is None:
        fetched = _checked_request(parent_url)
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
        absolute, _fragment = urldefrag(urljoin(parent_url, href))
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        host = parsed.hostname.lower()
        if is_ssrf_risk(host):
            continue
        registered = registered_domain(host)
        if registered == parent_registered_domain:
            internal.setdefault(absolute, text)
        else:
            external.setdefault(absolute, text)
    policies = {origin: robots}
    def allowed(url):
        try:
            parsed = urlparse(url)
            if (parsed.scheme not in {"https", "http"} or not parent_registered_domain or
                    registered_domain(parsed.hostname) != parent_registered_domain or
                    parsed.username is not None or parsed.port not in (None, 80, 443)):
                return False
            site = urljoin(url, "/")
            if site not in policies:
                policies[site] = _robots_policy(site)
            policy = policies[site]
            return policy is None or policy.can_fetch(USER_AGENT, url)
        except ValueError:
            return False

    # Only homepage links are observations. Sitemap and conventional paths must
    # respond successfully before being listed. Never follow their redirects.
    candidates = list(sorted(internal, key=lambda u: _priority(u, internal[u])))
    if len(internal) < 5 and parent_registered_domain:
        maps = [urljoin(origin, "/sitemap.xml")]
        for sitemap in maps:
            if not allowed(sitemap):
                continue
            time.sleep(0.12)
            response = _checked_request(sitemap, max_redirects=0, max_bytes=131072)
            xml = response.get("body", "")
            if response.get("status_code") != 200 or "<!DOCTYPE" in xml.upper():
                continue
            try:
                root = ET.fromstring(xml)
            except ET.ParseError:
                continue
            for loc in root.findall(".//{*}loc"):
                target = (loc.text or "").strip()
                if registered_domain(urlparse(target).hostname) != parent_registered_domain:
                    continue
                if root.tag.split("}")[-1] == "sitemapindex":
                    if len(maps) < 3 and target not in maps:
                        maps.append(target)
                elif len(candidates) < MAX_LINKS and target not in candidates:
                    candidates.append(target)
        candidates.extend(urljoin(origin, "/" + path) for path in (
            "login signin signup register account payment checkout contact about admissions "
            "academics placements departments support").split())
    results = []
    about_text = ""
    for url in list(dict.fromkeys(candidates))[:MAX_LINKS - min(len(external), 3)]:
        if not allowed(url):
            if url in internal:
                results.append({"url": url, "verdict": "Unverified", "same_registered_domain": True,
                                "reason": "Inspection disallowed by robots.txt or destination policy."})
            continue
        time.sleep(0.12)
        row = _inspect_subpage(url, parent_registered_domain, parent_genuine)
        if url not in internal and not 200 <= (row.get("http_status") or 0) < 400:
            continue
        text = row.pop("about_text", "")
        about_text = about_text or text
        if url not in internal and any(r.get("final_url") == row.get("final_url") for r in results):
            continue
        results.append(row)
    slots = max(0, MAX_LINKS - len(results))
    for url, text in sorted(external.items(), key=lambda pair: _priority(pair[0], pair[1]))[:slots]:
        results.append({"url": url, "final_url": None, "same_registered_domain": False,
                        "https": url.startswith("https://"), "tls_valid": None, "http_status": None,
                        "reachable": None, "verdict": "Third-party",
                        "reason": "External link (including payment gateways) is listed separately and is not assumed genuine.",
                        "red_flags": [], "ml_verdict": None, "risk_score": None})
    about = urljoin(origin, "/about")
    if not about_text and about not in candidates and allowed(about):
        time.sleep(0.12)
        response = _checked_request(about, max_redirects=0)
        if response.get("status_code") == 200 and "html" in response.get("content_type", ""):
            page = BeautifulSoup(response.get("body", ""), "html.parser")
            about_text = " ".join(p.get_text(" ", strip=True) for p in page.select("p")[:8])[:2500]
    for row in results:
        row["domain"] = registered_domain(urlparse(row.get("final_url") or row["url"]).hostname)
    verified = sum(result["verdict"] == "Genuine" for result in results)
    flagged = len(results) - verified
    return {"enabled": True,
            "about_text": about_text,
            "message": ("Few links found; the site may build its menu with JavaScript. " if len(results) < 5 else "") + f"{verified}/{len(results)} discovered links verified genuine; {flagged} flagged or external.",
            "verified_count": verified, "flagged_count": flagged, "total_count": len(results),
            "links": results}

