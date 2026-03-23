from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup

from scanner.crawler.form_parser import extract_forms
from scanner.crawler.models import FormModel


def parse_html_document(
    html: str,
    base_url: str,
) -> tuple[set[str], set[str], list[FormModel], set[str]]:
    soup = BeautifulSoup(html, "html.parser")

    links: set[str] = set()
    js_files: set[str] = set()
    inline_scripts: set[str] = set()

    for anchor in soup.find_all("a", href=True):
        links.add(urljoin(base_url, anchor["href"].strip()))

    for script in soup.find_all("script"):
        src = (script.get("src") or "").strip()
        if src:
            js_files.add(urljoin(base_url, src))
        else:
            text = script.text.strip()
            if text:
                inline_scripts.add(text)

    forms = extract_forms(html, base_url)

    for link in soup.find_all("link", href=True):
        href = link["href"].strip()
        if href.endswith(".js"):
            js_files.add(urljoin(base_url, href))

    return links, js_files, forms, inline_scripts
