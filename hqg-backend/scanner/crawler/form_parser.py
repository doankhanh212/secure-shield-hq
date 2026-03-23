from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup

from scanner.crawler.models import FormModel


def extract_forms(html: str, base_url: str) -> list[FormModel]:
    soup = BeautifulSoup(html, "html.parser")
    forms: list[FormModel] = []

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "GET").strip().upper()

        normalized_action = urljoin(base_url, action) if action else base_url

        fields: list[str] = []
        for field in form.find_all(["input", "select", "textarea"]):
            name = (field.get("name") or "").strip()
            if name:
                fields.append(name)

        forms.append(FormModel(action=normalized_action, method=method, fields=sorted(set(fields))))

    return forms
