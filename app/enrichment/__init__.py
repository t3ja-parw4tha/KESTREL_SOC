"""Enrichment package: threat intelligence orchestration."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from app.config import get_settings
from app.enrichment.abuseipdb import AbuseIPDBClient, AbuseResult
from app.enrichment.feeds import FeedMatch, ThreatFeedManager
from app.enrichment.ioc_extractor import IOCExtractor, IOCResults
from app.enrichment.virustotal import VTResult, VirusTotalClient


@dataclass
class EnrichmentResult:
    """Result of enriching an alert."""

    iocs_found: IOCResults
    vt_results: list[VTResult] = field(default_factory=list)
    abuse_results: list[AbuseResult] = field(default_factory=list)
    feed_matches: list[FeedMatch] = field(default_factory=list)
    risk_modifier: int = 0
    summary: str = ""


class EnrichmentOrchestrator:
    """Orchestrate IOC extraction, VT/AbuseIPDB lookups, and feed matching."""

    def __init__(self) -> None:
        settings = get_settings()
        vt_key = settings.virustotal_api_key.get_secret_value() or ""
        abuse_key = settings.abuseipdb_api_key.get_secret_value() or ""
        self._vt = VirusTotalClient(vt_key) if vt_key else None
        self._abuse = AbuseIPDBClient(abuse_key) if abuse_key else None
        self._feeds = ThreatFeedManager()
        self._ioc = IOCExtractor()

    async def enrich_alert(self, alert) -> EnrichmentResult:
        """
        Enrich an alert: extract IOCs, run VT/AbuseIPDB for IPs, check feeds.
        Gracefully skips sources without API keys.
        """
        raw = alert.raw or {}
        text = json.dumps(raw) if isinstance(raw, dict) else str(raw)
        iocs = self._ioc.extract(text)

        vt_results: list[VTResult] = []
        abuse_results: list[AbuseResult] = []
        feed_matches: list[FeedMatch] = []
        risk_modifier = 0

        ip_tasks: list[Any] = []
        if self._vt:
            for ip in iocs.ips:
                ip_tasks.append(self._vt.lookup_ip(ip))
        if self._abuse:
            for ip in iocs.ips:
                ip_tasks.append(self._abuse.lookup_ip(ip))

        if ip_tasks:
            gathered = await asyncio.gather(*ip_tasks, return_exceptions=True)
            for r in gathered:
                if isinstance(r, Exception):
                    continue
                if isinstance(r, VTResult):
                    vt_results.append(r)
                    if r.error:
                        continue
                    if r.malicious_count >= 5:
                        risk_modifier += 15
                    elif r.malicious_count >= 1:
                        risk_modifier += 10
                    elif r.suspicious_count >= 3:
                        risk_modifier += 5
                elif isinstance(r, AbuseResult):
                    abuse_results.append(r)
                    if r.abuse_score >= 80:
                        risk_modifier += 15
                    elif r.abuse_score >= 50:
                        risk_modifier += 10
                    elif r.abuse_score >= 25:
                        risk_modifier += 5

        if self._vt:
            for domain in iocs.domains[:10]:
                try:
                    vt_d = await self._vt.lookup_domain(domain)
                    vt_results.append(vt_d)
                    if not vt_d.error and vt_d.malicious_count >= 3:
                        risk_modifier += 10
                except Exception:
                    pass
            for h in iocs.hashes[:5]:
                try:
                    vt_h = await self._vt.lookup_hash(h)
                    vt_results.append(vt_h)
                    if not vt_h.error and vt_h.malicious_count >= 3:
                        risk_modifier += 15
                except Exception:
                    pass

        for ind in iocs.ips + iocs.domains + iocs.cves:
            match = self._feeds.is_known_bad(ind)
            if match:
                feed_matches.append(match)
                risk_modifier += 20

        summary_parts = []
        if iocs.ips:
            summary_parts.append(f"{len(iocs.ips)} IP(s)")
        if iocs.domains:
            summary_parts.append(f"{len(iocs.domains)} domain(s)")
        if iocs.hashes:
            summary_parts.append(f"{len(iocs.hashes)} hash(es)")
        if iocs.cves:
            summary_parts.append(f"{len(iocs.cves)} CVE(s)")
        if feed_matches:
            summary_parts.append(f"{len(feed_matches)} feed match(es)")
        summary = "; ".join(summary_parts) if summary_parts else "No IOCs extracted"

        return EnrichmentResult(
            iocs_found=iocs,
            vt_results=vt_results,
            abuse_results=abuse_results,
            feed_matches=feed_matches,
            risk_modifier=risk_modifier,
            summary=summary,
        )
