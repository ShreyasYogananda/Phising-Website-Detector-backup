"""Extract a cautious, short description from already-fetched page HTML."""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

CATEGORIES = {
    "e-commerce": ("shop", "store", "cart", "checkout", "product", "buy", "order"),
    "banking / finance": ("bank", "account", "payment", "wallet", "loan", "finance", "invest"),
    "gaming": ("game", "gaming", "play", "steam", "xbox", "playstation"),
    "education": ("school", "university", "course", "learn", "education", "student"),
    "social media": ("social", "community", "profile", "friends", "share", "feed"),
    "government": ("government", "gov.in", "gov.uk", ".gov", "ministry", "public service"),
    "news / media": ("news", "journal", "media", "press", "magazine", "article"),
    "technology": ("software", "technology", "cloud", "developer", "api", "digital"),
}


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def describe_site(html: str | None, final_url: str | None, reachable: bool = True) -> dict:
    """Build a 2–3 sentence extractive summary; never invent unreachable content."""
    if not reachable or not html:
        return {"available": False, "category": "Unknown",
                "description": "The website is unreachable, so no description is available."}
    soup = BeautifulSoup(html[:512 * 1024], "html.parser")
    for node in soup(["script", "style", "noscript", "svg", "iframe"]):
        node.decompose()
    for node in soup.find_all(attrs={"hidden": True}):
        node.decompose()
    for node in soup.find_all(attrs={"aria-hidden": "true"}):
        node.decompose()
    for node in soup.find_all(style=re.compile(r"(?:display\s*:\s*none|visibility\s*:\s*hidden)", re.I)):
        node.decompose()
    title = _clean(soup.title.get_text(" ", strip=True)) if soup.title else ""
    description = ""
    for attrs in ({"name": "description"}, {"property": "og:description"}):
        meta = soup.find("meta", attrs=attrs)
        if meta and meta.get("content"):
            description = _clean(meta["content"])
            if description:
                break
    headings = [_clean(h.get_text(" ", strip=True)) for h in soup.find_all(["h1", "h2"], limit=5)]
    headings = [h for h in headings if h]
    visible = _clean(soup.get_text(" ", strip=True))[:700]
    evidence = " ".join([final_url or "", title, description, " ".join(headings), visible]).lower()
    category = "general website"
    best = 0
    for label, terms in CATEGORIES.items():
        count = sum(term in evidence for term in terms)
        if count > best:
            category, best = label, count
    chosen = description or (". ".join(headings[:2])) or visible
    if title and chosen and title.lower() not in chosen.lower():
        chosen = f"{title}: {chosen}"
    if not chosen:
        chosen = f"The page at {final_url or 'this address'} contains no readable description text."
    # Truncate at a sentence boundary when possible; keep the source-derived text.
    chosen = _clean(chosen)
    if len(chosen) > 420:
        sentence = re.split(r"(?<=[.!?])\s+", chosen[:420])
        chosen = " ".join(sentence[:-1]) if len(sentence) > 1 else chosen[:417].rstrip() + "..."
    return {"available": True, "category": category,
            "description": chosen, "source": "Page title, metadata, headings, and visible text"}

