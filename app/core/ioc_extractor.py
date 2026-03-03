"""Simple IOC extractor for ingested events."""

from __future__ import annotations

import re
from typing import Any

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,63})\b"
)
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def extract_iocs(raw: dict[str, Any] | None) -> dict[str, list[str]]:
    """
    Extract simple IOCs (IPs, domains, hashes) from a raw payload.
    Best-effort, safe for arbitrary JSON structures.
    """
    if not raw:
        return {"ips": [], "domains": [], "hashes": []}

    text = str(raw)
    ips = sorted(set(IP_PATTERN.findall(text)))
    domains = sorted(set(DOMAIN_PATTERN.findall(text)))
    hashes = sorted(set(HASH_PATTERN.findall(text)))

    return {"ips": ips, "domains": domains, "hashes": hashes}

