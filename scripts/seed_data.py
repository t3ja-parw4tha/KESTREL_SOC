#!/usr/bin/env python3
"""
Seed the KESTREL SOC platform with realistic sample alerts.

Usage:
    python -m scripts.seed_data
"""

import argparse
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

BASE_URL = "http://localhost:8000"

# Simple ANSI colors for terminal output
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def _iso(ts: str) -> str:
    """Return ISO timestamp; helper so all samples are valid ISO strings."""
    # If user passes already-ISO, just return; otherwise attempt to parse.
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


ALERTS: List[Dict[str, Any]] = [
    # Sentinel: BruteForce (High)
    {
        "source": "Sentinel",
        "events": [
            {
                "Severity": "High",
                "DisplayName": "Multiple failed logins from 185.220.101.45",
                "AlertType": "BruteForce",
                "Category": "Auth",
                "UserPrincipalName": "jdoe@contoso.com",
                "SourceIP": "185.220.101.45",
                "CompromisedEntity": "WS-001",
                "StartTime": _iso("2026-03-02T00:10:00Z"),
            }
        ],
    },
    # Sentinel: Lateral Movement (modeled via category)
    {
        "source": "Sentinel",
        "events": [
            {
                "Severity": "High",
                "DisplayName": "Suspicious lateral movement from server-001",
                "AlertType": "LateralMovement",
                "Category": "Lateral Movement",
                "UserPrincipalName": "svc-app@contoso.com",
                "SourceIP": "10.0.0.5",
                "CompromisedEntity": "SRV-APP-01",
                "StartTime": _iso("2026-03-02T00:15:00Z"),
            }
        ],
    },
    # Sentinel: Privilege Escalation
    {
        "source": "Sentinel",
        "events": [
            {
                "Severity": "High",
                "DisplayName": "Suspicious privilege escalation on DC-01",
                "AlertType": "PrivilegeEscalation",
                "Category": "Privilege Escalation",
                "UserPrincipalName": "admin-temp@contoso.com",
                "SourceIP": "10.0.0.10",
                "CompromisedEntity": "DC-01",
                "StartTime": _iso("2026-03-02T00:18:00Z"),
            }
        ],
    },
    # Suricata: CobaltStrike (Critical)
    {
        "source": "Suricata",
        "events": [
            {
                "event_type": "alert",
                "src_ip": "10.0.0.5",
                "dest_ip": "185.220.101.45",
                "alert": {
                    "severity": 1,
                    "signature": "ET MALWARE CobaltStrike Beacon",
                    "category": "Malware",
                },
                "timestamp": _iso("2026-03-02T00:20:00Z"),
            }
        ],
    },
    # Suricata: Port Scan (Medium)
    {
        "source": "Suricata",
        "events": [
            {
                "event_type": "alert",
                "src_ip": "203.0.113.10",
                "dest_ip": "10.0.0.20",
                "alert": {
                    "severity": 3,
                    "signature": "ET SCAN Potential SSH Scan",
                    "category": "Network",
                },
                "timestamp": _iso("2026-03-02T00:22:00Z"),
            }
        ],
    },
    # Suricata: DNS Tunnel (High)
    {
        "source": "Suricata",
        "events": [
            {
                "event_type": "alert",
                "src_ip": "10.0.0.15",
                "dest_ip": "198.51.100.50",
                "alert": {
                    "severity": 2,
                    "signature": "ET TROJAN Possible DNS Tunneling",
                    "category": "Network",
                },
                "timestamp": _iso("2026-03-02T00:24:00Z"),
            }
        ],
    },
    # WindowsEventLog: 4625 Failed Login (Medium/High Auth)
    {
        "source": "WindowsEventLog",
        "events": [
            {
                "EventID": 4625,
                "EventData": {
                    "SubjectUserName": "SYSTEM",
                    "TargetUserName": "administrator",
                    "IpAddress": "192.168.1.100",
                },
                "TimeCreated": _iso("2026-03-02T00:26:00Z"),
                "Message": "An account failed to log on.",
            }
        ],
    },
    # WindowsEventLog: 4720 New Admin Created (High Persistence)
    {
        "source": "WindowsEventLog",
        "events": [
            {
                "EventID": 4720,
                "EventData": {
                    "SubjectUserName": "DOMAIN\\Administrator",
                    "TargetUserName": "svc-admin",
                    "IpAddress": "192.168.1.50",
                },
                "TimeCreated": _iso("2026-03-02T00:28:00Z"),
                "Message": "A user account was created.",
            }
        ],
    },
    # WindowsEventLog: 4688 Suspicious process (Mimikatz-like)
    {
        "source": "WindowsEventLog",
        "events": [
            {
                "EventID": 4688,
                "EventData": {
                    "SubjectUserName": "DOMAIN\\admin",
                    "TargetUserName": "admin",
                    "IpAddress": "192.168.1.75",
                },
                "TimeCreated": _iso("2026-03-02T00:30:00Z"),
                "Message": "A new process has been created: mimikatz.exe",
            }
        ],
    },
    # Defender: Ransomware (Critical)
    {
        "source": "Defender",
        "events": [
            {
                "title": "Ransomware behavior detected",
                "severity": "Critical",
                "category": "Impact",
                "devices": [
                    {
                        "deviceDnsName": "DESKTOP-ABC123",
                        "networkInterfaces": [{"ipAddress": "10.0.0.30"}],
                    }
                ],
                "relatedUser": {"userName": "victim@contoso.com"},
                "alertCreationTime": _iso("2026-03-02T00:32:00Z"),
                "mitreTechniques": [{"id": "T1486", "category": "Impact"}],
            }
        ],
    },
    # Defender: Emotet (High)
    {
        "source": "Defender",
        "events": [
            {
                "title": "Emotet malware detected in email attachment",
                "severity": "High",
                "category": "Execution",
                "devices": [
                    {
                        "deviceDnsName": "LAPTOP-USER01",
                        "networkInterfaces": [{"ipAddress": "10.0.0.31"}],
                    }
                ],
                "relatedUser": {"userName": "user1@contoso.com"},
                "alertCreationTime": _iso("2026-03-02T00:34:00Z"),
                "mitreTechniques": [{"id": "T1204", "category": "Execution"}],
            }
        ],
    },
    # GuardDuty: SSH Brute Force (High)
    {
        "source": "GuardDuty",
        "events": [
            {
                "title": "EC2 instance is being probed on port 22",
                "severity": 7.5,
                "type": "UnauthorizedAccess:EC2/SSHBruteForce",
                "resource": {
                    "instanceDetails": {
                        "instanceId": "i-0123456789abcdef0",
                    }
                },
                "service": {
                    "action": {
                        "networkConnectionAction": {
                            "remoteIpDetails": {"ipAddressV4": "185.220.101.45"}
                        }
                    }
                },
                "createdAt": _iso("2026-03-02T00:36:00Z"),
            }
        ],
    },
    # GuardDuty: Crypto Mining (High)
    {
        "source": "GuardDuty",
        "events": [
            {
                "title": "EC2 instance suspected of crypto mining",
                "severity": 7.0,
                "type": "CryptoCurrency:EC2/BitcoinTool.B",
                "resource": {
                    "instanceDetails": {
                        "instanceId": "i-0fedcba9876543210",
                    }
                },
                "service": {
                    "action": {
                        "networkConnectionAction": {
                            "remoteIpDetails": {"ipAddressV4": "203.0.113.200"}
                        }
                    }
                },
                "createdAt": _iso("2026-03-02T00:38:00Z"),
            }
        ],
    },
    # Snort: SQL Injection (Medium) via GenericParser
    {
        "source": "Snort",
        "events": [
            {
                "severity": "Medium",
                "title": "SQL Injection attempt detected on /login",
                "src_ip": "203.0.113.5",
                "dest_ip": "10.0.0.40",
                "timestamp": _iso("2026-03-02T00:40:00Z"),
            }
        ],
    },
    # Syslog: Crontab Persistence (High) via GenericParser
    {
        "source": "Syslog",
        "events": [
            {
                "severity": "High",
                "title": "User root edited crontab",
                "host": "linux-web-01",
                "message": "CRON: (root) CMD (/usr/bin/python /opt/persist.py)",
                "timestamp": _iso("2026-03-02T00:42:00Z"),
            }
        ],
    },
]


async def main() -> None:
    parser = argparse.ArgumentParser(description="Seed KESTREL with sample alerts")
    parser.add_argument("--username", default="socadmin")
    parser.add_argument("--password", default="Soc2026!Pass")
    parser.add_argument("--base-url", default=BASE_URL)
    args = parser.parse_args()

    async with httpx.AsyncClient(base_url=args.base_url, timeout=10) as client:
        # Login
        print(f"{YELLOW}[*]{RESET} Logging in as {args.username} at {args.base_url} ...")
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": args.username, "password": args.password},
        )
        if resp.status_code != 200:
            print(f"{RED}[!]{RESET} Login failed: {resp.status_code} {resp.text}")
            return
        token = resp.json().get("access_token")
        if not token:
            print(f"{RED}[!]{RESET} Login response missing access_token")
            return
        headers = {"Authorization": f"Bearer {token}"}
        print(f"{GREEN}[+]{RESET} Login successful.")

        passed = 0
        failed = 0

        for idx, alert in enumerate(ALERTS, start=1):
            source = alert.get("source", "<unknown>")
            try:
                r = await client.post("/api/v1/ingest", json=alert, headers=headers)
            except Exception as e:  # network or serialization error
                failed += 1
                print(f"{RED}[{idx:02d}] FAIL{RESET} {source}: exception {e}")
                continue

            if r.status_code == 200:
                passed += 1
                print(f"{GREEN}[{idx:02d}] OK  {RESET}{source}")
            else:
                failed += 1
                print(f"{RED}[{idx:02d}] FAIL{RESET} {source}: {r.status_code} {r.text}")

        print(f"\nSeed complete: {GREEN}{passed} ingested{RESET}, {RED}{failed} failed{RESET}")


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""Seed database with sample data (stub)."""

def main():
    print("Seed data (stub) - implement as needed.")


if __name__ == "__main__":
    main()
