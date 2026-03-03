"""AbuseIPDB API client for threat intelligence enrichment."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.enrichment.cache import get as cache_get, set as cache_set

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

CATEGORY_IDS: dict[int, str] = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute Force",
    18: "Brute Force",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
}


@dataclass
class AbuseResult:
    """AbuseIPDB lookup result."""

    ip: str
    abuse_score: int
    isp: str | None
    usage_type: str | None
    country_code: str | None
    total_reports: int
    categories: list[str]
    permalink: str | None
    cached: bool


class AbuseIPDBClient:
    """AbuseIPDB API client for IP reputation checks."""

    def __init__(self, api_key: str):
        self._api_key = api_key

    async def lookup_ip(
        self,
        ip: str,
        max_age_days: int = 90,
    ) -> AbuseResult:
        """Lookup IP address. Checks cache before API call."""
        cached = cache_get(ip, "abuseipdb")
        if cached is not None:
            return AbuseResult(
                ip=ip,
                abuse_score=cached.get("abuse_score", 0),
                isp=cached.get("isp"),
                usage_type=cached.get("usage_type"),
                country_code=cached.get("country_code"),
                total_reports=cached.get("total_reports", 0),
                categories=cached.get("categories", []),
                permalink=cached.get("permalink"),
                cached=True,
            )
        if not self._api_key:
            return AbuseResult(
                ip=ip,
                abuse_score=0,
                isp=None,
                usage_type=None,
                country_code=None,
                total_reports=0,
                categories=[],
                permalink=None,
                cached=False,
            )
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.get(
                    f"{ABUSEIPDB_BASE}/check",
                    params={"ipAddress": ip, "maxAgeInDays": max_age_days},
                    headers={
                        "Key": self._api_key,
                        "Accept": "application/json",
                    },
                )
                r.raise_for_status()
                data = r.json().get("data", {}) or {}
                cat_ids = data.get("reports", [])
                if isinstance(cat_ids, list) and cat_ids:
                    cat_ids = cat_ids[0].get("categories", []) or []
                elif isinstance(data.get("reports"), list) and data["reports"]:
                    cat_ids = data["reports"][0].get("categories", []) or []
                else:
                    cat_ids = data.get("category_ids") or []
                if not isinstance(cat_ids, list):
                    cat_ids = [cat_ids] if cat_ids else []
                categories = []
                for c in cat_ids:
                    if c is None:
                        continue
                    try:
                        categories.append(CATEGORY_IDS.get(int(c), str(c)))
                    except (ValueError, TypeError):
                        categories.append(str(c))
                result = AbuseResult(
                    ip=ip,
                    abuse_score=int(data.get("abuseConfidenceScore", 0)),
                    isp=data.get("isp"),
                    usage_type=data.get("usageType"),
                    country_code=data.get("countryCode"),
                    total_reports=int(data.get("totalReports", 0)),
                    categories=categories,
                    permalink=f"https://www.abuseipdb.com/check/{ip}",
                    cached=False,
                )
                cache_set(
                    ip,
                    "ip",
                    "abuseipdb",
                    {
                        "abuse_score": result.abuse_score,
                        "isp": result.isp,
                        "usage_type": result.usage_type,
                        "country_code": result.country_code,
                        "total_reports": result.total_reports,
                        "categories": result.categories,
                        "permalink": result.permalink,
                    },
                )
                return result
        except Exception:
            return AbuseResult(
                ip=ip,
                abuse_score=0,
                isp=None,
                usage_type=None,
                country_code=None,
                total_reports=0,
                categories=[],
                permalink=None,
                cached=False,
            )
