"""IOC extractor for threat intelligence enrichment."""

from __future__ import annotations

import re
from dataclasses import dataclass

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b")

BENIGN_TLDS = frozenset(
    {"com", "org", "net", "edu", "gov", "mil", "int", "co", "io", "info", "biz"}
)


def _is_rfc1918(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b, c, d = (int(p) for p in parts)
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    return False


def _defang(s: str) -> str:
    """Replace . with [.] for display."""
    return s.replace(".", "[.]")


@dataclass
class IOCResults:
    """Extracted IOCs with optional defanged display forms."""

    ips: list[str]
    domains: list[str]
    hashes: list[str]
    cves: list[str]
    ips_defanged: list[str] | None = None
    domains_defanged: list[str] | None = None

    def __post_init__(self) -> None:
        if self.ips_defanged is None:
            self.ips_defanged = [_defang(ip) for ip in self.ips]
        if self.domains_defanged is None:
            self.domains_defanged = [_defang(d) for d in self.domains]


class IOCExtractor:
    """Extract indicators of compromise from text."""

    def extract(self, text: str) -> IOCResults:
        """Extract IPs, domains, hashes, CVEs from text. Filter RFC1918 IPs."""
        if not text or not isinstance(text, str):
            return IOCResults(ips=[], domains=[], hashes=[], cves=[])

        ips_raw = IPV4_PATTERN.findall(text)
        ips = sorted(set(ip for ip in ips_raw if not _is_rfc1918(ip)))

        domains_raw = DOMAIN_PATTERN.findall(text)
        domains = []
        seen = set()
        for d in domains_raw:
            d_lower = d.lower()
            if d_lower in seen:
                continue
            tld = d_lower.rsplit(".", 1)[-1] if "." in d_lower else ""
            if tld in BENIGN_TLDS and len(domains_raw) > 50:
                continue
            seen.add(d_lower)
            domains.append(d)
        domains = sorted(domains)

        md5 = sorted(set(MD5_PATTERN.findall(text)))
        sha1 = sorted(set(SHA1_PATTERN.findall(text)))
        sha256 = sorted(set(SHA256_PATTERN.findall(text)))
        hashes = sorted(set(md5 + sha1 + sha256))

        cves = sorted(set(CVE_PATTERN.findall(text)))

        return IOCResults(
            ips=ips,
            domains=domains,
            hashes=hashes,
            cves=cves,
        )
