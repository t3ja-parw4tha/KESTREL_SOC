"""VirusTotal API client for threat intelligence enrichment."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import httpx

from app.enrichment.cache import get as cache_get, set as cache_set


@dataclass
class VTResult:
    """VirusTotal lookup result."""

    indicator: str
    malicious_count: int
    suspicious_count: int
    total_engines: int
    detection_ratio: float
    threat_categories: list[str]
    permalink: str | None
    cached: bool
    error: str | None


VT_BASE = "https://www.virustotal.com/api/v3"
RATE_LIMIT_DELAY = 15.0  # 4 req/min = 1 every 15 seconds


class VirusTotalClient:
    """VirusTotal API client with rate limiting and cache."""

    def __init__(self, api_key: str):
        self._api_key = api_key
        self._last_request_time: float = 0
        self._lock = asyncio.Lock()

    async def _rate_limit(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < RATE_LIMIT_DELAY:
                await asyncio.sleep(RATE_LIMIT_DELAY - elapsed)
            self._last_request_time = time.monotonic()

    def _parse_stats(self, data: dict[str, Any], indicator: str) -> VTResult:
        attrs = data.get("data", {}).get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected
        ratio = (malicious + suspicious) / total if total > 0 else 0.0
        meta = data.get("data", {}).get("meta", {}) or {}
        link = meta.get("url") or attrs.get("permalink")
        cats = attrs.get("categories", {}) or {}
        threat_cats = list(cats.values()) if isinstance(cats, dict) else []
        return VTResult(
            indicator=indicator,
            malicious_count=malicious,
            suspicious_count=suspicious,
            total_engines=total,
            detection_ratio=round(ratio, 4),
            threat_categories=threat_cats,
            permalink=link,
            cached=False,
            error=None,
        )

    async def lookup_ip(self, ip: str) -> VTResult:
        """Lookup IP address. Checks cache before API call."""
        cached = cache_get(ip, "virustotal")
        if cached is not None:
            return VTResult(
                indicator=ip,
                malicious_count=cached.get("malicious_count", 0),
                suspicious_count=cached.get("suspicious_count", 0),
                total_engines=cached.get("total_engines", 0),
                detection_ratio=cached.get("detection_ratio", 0.0),
                threat_categories=cached.get("threat_categories", []),
                permalink=cached.get("permalink"),
                cached=True,
                error=None,
            )
        if not self._api_key:
            return VTResult(
                indicator=ip,
                malicious_count=0,
                suspicious_count=0,
                total_engines=0,
                detection_ratio=0.0,
                threat_categories=[],
                permalink=None,
                cached=False,
                error="API key not configured",
            )
        await self._rate_limit()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.get(
                    f"{VT_BASE}/ip_addresses/{ip}",
                    headers={
                        "x-apikey": self._api_key,
                        "Accept": "application/json",
                    },
                )
                r.raise_for_status()
                data = r.json()
                result = self._parse_stats(data, ip)
                cache_set(
                    ip,
                    "ip",
                    "virustotal",
                    {
                        "malicious_count": result.malicious_count,
                        "suspicious_count": result.suspicious_count,
                        "total_engines": result.total_engines,
                        "detection_ratio": result.detection_ratio,
                        "threat_categories": result.threat_categories,
                        "permalink": result.permalink,
                    },
                )
                return result
        except Exception as e:
            return VTResult(
                indicator=ip,
                malicious_count=0,
                suspicious_count=0,
                total_engines=0,
                detection_ratio=0.0,
                threat_categories=[],
                permalink=None,
                cached=False,
                error=str(e),
            )

    async def lookup_domain(self, domain: str) -> VTResult:
        """Lookup domain. Checks cache before API call."""
        cached = cache_get(domain, "virustotal")
        if cached is not None:
            return VTResult(
                indicator=domain,
                malicious_count=cached.get("malicious_count", 0),
                suspicious_count=cached.get("suspicious_count", 0),
                total_engines=cached.get("total_engines", 0),
                detection_ratio=cached.get("detection_ratio", 0.0),
                threat_categories=cached.get("threat_categories", []),
                permalink=cached.get("permalink"),
                cached=True,
                error=None,
            )
        if not self._api_key:
            return VTResult(
                indicator=domain,
                malicious_count=0,
                suspicious_count=0,
                total_engines=0,
                detection_ratio=0.0,
                threat_categories=[],
                permalink=None,
                cached=False,
                error="API key not configured",
            )
        await self._rate_limit()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.get(
                    f"{VT_BASE}/domains/{domain}",
                    headers={
                        "x-apikey": self._api_key,
                        "Accept": "application/json",
                    },
                )
                r.raise_for_status()
                data = r.json()
                result = self._parse_stats(data, domain)
                cache_set(
                    domain,
                    "domain",
                    "virustotal",
                    {
                        "malicious_count": result.malicious_count,
                        "suspicious_count": result.suspicious_count,
                        "total_engines": result.total_engines,
                        "detection_ratio": result.detection_ratio,
                        "threat_categories": result.threat_categories,
                        "permalink": result.permalink,
                    },
                )
                return result
        except Exception as e:
            return VTResult(
                indicator=domain,
                malicious_count=0,
                suspicious_count=0,
                total_engines=0,
                detection_ratio=0.0,
                threat_categories=[],
                permalink=None,
                cached=False,
                error=str(e),
            )

    async def lookup_hash(self, hash_val: str) -> VTResult:
        """Lookup file hash (MD5, SHA1, SHA256). Checks cache before API call."""
        cached = cache_get(hash_val, "virustotal")
        if cached is not None:
            return VTResult(
                indicator=hash_val,
                malicious_count=cached.get("malicious_count", 0),
                suspicious_count=cached.get("suspicious_count", 0),
                total_engines=cached.get("total_engines", 0),
                detection_ratio=cached.get("detection_ratio", 0.0),
                threat_categories=cached.get("threat_categories", []),
                permalink=cached.get("permalink"),
                cached=True,
                error=None,
            )
        if not self._api_key:
            return VTResult(
                indicator=hash_val,
                malicious_count=0,
                suspicious_count=0,
                total_engines=0,
                detection_ratio=0.0,
                threat_categories=[],
                permalink=None,
                cached=False,
                error="API key not configured",
            )
        await self._rate_limit()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.get(
                    f"{VT_BASE}/files/{hash_val}",
                    headers={
                        "x-apikey": self._api_key,
                        "Accept": "application/json",
                    },
                )
                r.raise_for_status()
                data = r.json()
                result = self._parse_stats(data, hash_val)
                cache_set(
                    hash_val,
                    "hash",
                    "virustotal",
                    {
                        "malicious_count": result.malicious_count,
                        "suspicious_count": result.suspicious_count,
                        "total_engines": result.total_engines,
                        "detection_ratio": result.detection_ratio,
                        "threat_categories": result.threat_categories,
                        "permalink": result.permalink,
                    },
                )
                return result
        except Exception as e:
            return VTResult(
                indicator=hash_val,
                malicious_count=0,
                suspicious_count=0,
                total_engines=0,
                detection_ratio=0.0,
                threat_categories=[],
                permalink=None,
                cached=False,
                error=str(e),
            )
