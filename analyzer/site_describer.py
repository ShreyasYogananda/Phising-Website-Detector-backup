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
    if not reachable:
        return {"available": False, "category": "Unknown",
                "description": "The website is unreachable, so no description is available."}
    soup = BeautifulSoup((html or "")[:512 * 1024], "html.parser")
    for node in soup(["script", "style", "noscript", "svg", "iframe", "nav", "footer", "aside", "form"]):
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
    # Prefer a sentence explaining a service over a welcome slogan or a navigation label.
    main = soup.find("main") or soup.find("article") or soup
    paragraphs = [node.get_text(" ", strip=True) for node in main.find_all("p", limit=25)]
    purpose = re.compile(r"\b(helps?|allows?|lets?|provides?|offers?|connects?|enables?|"
                         r"find|search|book|learn|compare|track|sell|buy|manage|create|"
                         r"teaches?|publishes?|platform|marketplace|library|directory)\b", re.I)
    boilerplate = re.compile(r"accept (all )?cookies|cookie preferences|enable javascript|"
                             r"verify you are human|all rights reserved", re.I)
    candidates = []
    for passage in [description, *paragraphs, *headings, title]:
        for sentence in re.split(r"(?<=[.!?])\s+", _clean(passage)):
            if len(sentence.split()) < 4 or boilerplate.search(sentence):
                continue
            candidates.append((bool(purpose.search(sentence)), sentence))
    if not candidates:
        return {"available": False, "category": "Unknown",
                "description": "The page has too little descriptive text to explain what this website does."}
    candidates.sort(key=lambda item: item[0], reverse=True)
    sentences = list(dict.fromkeys(sentence for _, sentence in candidates))
    summary = sentences[0]
    if len(sentences) > 1 and candidates[0][0] and purpose.search(sentences[1]) and len(summary + sentences[1]) < 300:
        summary = summary.rstrip(".") + ". " + sentences[1]
    if len(summary) > 320:
        summary = summary[:317].rsplit(" ", 1)[0] + "..."
    return {"available": True, "category": category, "description": summary,
            "source": "Website metadata and visible page text"}
