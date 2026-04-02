"""Group crawled URLs by hostname."""
from __future__ import annotations

import logging
from collections import defaultdict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def group_by_host(urls: list[str]) -> dict[str, list[str]]:
    """Group a list of fully-qualified URLs by their hostname.

    Args:
        urls: Flat list of crawled endpoint URLs.

    Returns:
        Dict mapping each unique host to its list of URLs.
        URLs without a parseable host are silently dropped.
    """
    groups: dict[str, list[str]] = defaultdict(list)
    for url in urls:
        try:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc
            if host:
                groups[host].append(url)
        except Exception:
            continue

    logger.info(
        "host_grouper: %d URLs → %d unique hosts",
        len(urls),
        len(groups),
    )
    return dict(groups)
