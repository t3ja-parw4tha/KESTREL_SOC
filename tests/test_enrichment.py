"""Tests for enrichment: IOC extractor, VT, orchestrator."""

import asyncio
import os


from app.enrichment.ioc_extractor import IOCExtractor


def test_ioc_extractor_finds_public_ip():
    e = IOCExtractor()
    result = e.extract("connection from 8.8.8.8 on port 443")
    assert "8.8.8.8" in result.ips


def test_ioc_extractor_filters_rfc1918():
    e = IOCExtractor()
    result = e.extract("internal 192.168.1.1 and external 1.1.1.1")
    assert "192.168.1.1" not in result.ips
    assert "1.1.1.1" in result.ips


def test_ioc_extractor_finds_cve():
    e = IOCExtractor()
    result = e.extract("exploiting CVE-2021-44228 log4shell")
    assert "CVE-2021-44228" in result.cves


def test_ioc_extractor_finds_sha256():
    e = IOCExtractor()
    h = "a" * 64
    result = e.extract(f"hash: {h}")
    assert h in result.hashes


def test_ioc_extractor_defangs_ips():
    e = IOCExtractor()
    result = e.extract("bad ip 8.8.8.8")
    assert "8[.]8[.]8[.]8" in result.ips_defanged


def test_ioc_extractor_empty_input():
    e = IOCExtractor()
    result = e.extract("")
    assert result.ips == []
    assert result.domains == []
    assert result.hashes == []
    assert result.cves == []


def test_ioc_extractor_finds_domain():
    e = IOCExtractor()
    result = e.extract("C2 at evil.example.com")
    assert any("evil.example.com" in d for d in result.domains)


def test_vt_result_no_key_returns_error():
    from app.enrichment.virustotal import VirusTotalClient

    client = VirusTotalClient(api_key="")
    result = asyncio.run(client.lookup_ip("8.8.8.8"))
    assert result.error == "API key not configured"
    assert result.malicious_count == 0


def test_enrichment_result_no_keys_graceful():
    """With no API keys, orchestrator should still return an EnrichmentResult without crashing."""
    os.environ.setdefault("VIRUSTOTAL_API_KEY", "")
    os.environ.setdefault("ABUSEIPDB_API_KEY", "")

    from app.enrichment import EnrichmentOrchestrator

    class FakeAlert:
        raw = {"src_ip": "8.8.8.8", "message": "test CVE-2021-44228"}

    orchestrator = EnrichmentOrchestrator()
    result = asyncio.run(orchestrator.enrich_alert(FakeAlert()))
    assert result is not None
    assert "8.8.8.8" in result.iocs_found.ips
    assert "CVE-2021-44228" in result.iocs_found.cves
