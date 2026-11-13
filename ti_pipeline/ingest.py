"""Read the merged RSS feed and pull readable text out of each article."""
import logging
import re
from urllib.parse import urlparse

import feedparser
import requests
from bs4 import BeautifulSoup

from . import config

log = logging.getLogger(__name__)
_NOISE = [re.compile(p, re.I) for p in config.NOISE_TITLE_PATTERNS]


def fetch_feed(url: str, session: requests.Session) -> list[dict]:
    """Return feed items as dicts. Accepts a URL or a local file path (handy for testing)."""
    if url.startswith(("http://", "https://")):
        resp = session.get(url, timeout=config.HTTP_TIMEOUT)
        resp.raise_for_status()
        parsed = feedparser.parse(resp.content)
    else:
        parsed = feedparser.parse(url)

    items = []
    for e in parsed.entries:
        link = e.get("link")
        if not link:
            continue
        items.append({
            "title": (e.get("title") or "").strip(),
            "link": link.strip(),
            "published": e.get("published", ""),
            "source": urlparse(link).netloc.removeprefix("www."),
        })
    return items


def is_noise_title(title: str) -> bool:
    return any(p.search(title) for p in _NOISE)


def fetch_article_text(url: str, session: requests.Session) -> str:
    """Best-effort main-text extraction. Returns '' on failure; the pipeline still runs on the title."""
    try:
        resp = session.get(url, timeout=config.HTTP_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        log.warning("Could not fetch %s: %s", url, exc)
        return ""

    soup = BeautifulSoup(resp.text, "html.parser")
    for tag in soup(["script", "style", "noscript", "nav", "header", "footer",
                     "aside", "form", "iframe", "svg"]):
        tag.decompose()

    # Prefer the article body so "related posts" sidebars don't leak unrelated CVEs in.
    root = soup.find("article") or soup.find("main") or soup.body or soup
    text = " ".join(root.get_text(" ").split())
    return text[: config.MAX_ARTICLE_CHARS]
