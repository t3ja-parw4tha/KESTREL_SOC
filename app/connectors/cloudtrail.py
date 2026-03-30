"""AWS CloudTrail pull connector via LookupEvents API."""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class CloudTrailConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "aws-cloudtrail"

    @property
    def source_name(self) -> str:
        return "CloudTrail"

    def _client(self):  # type: ignore[no-untyped-def]
        import boto3
        s = get_settings()
        region = (s.aws_region or "us-east-1").strip()
        kw: dict[str, Any] = {"region_name": region}
        if s.aws_access_key_id and s.aws_secret_access_key.get_secret_value():
            kw["aws_access_key_id"] = s.aws_access_key_id
            kw["aws_secret_access_key"] = s.aws_secret_access_key.get_secret_value()
        return boto3.client("cloudtrail", **kw)

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.aws_access_key_id or not s.aws_secret_access_key.get_secret_value():
            return False, "AWS credentials not configured"
        try:
            client = self._client()
            await asyncio.to_thread(client.describe_trails, includeShadowTrails=False)
            return True, "OK"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.aws_access_key_id or not s.aws_secret_access_key.get_secret_value():
            return []
        # Suspicious event names to filter for
        SUSPICIOUS_EVENTS = {
            "ConsoleLogin", "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
            "GetSecretValue", "DeleteTrail", "StopLogging", "CreateUser", "AttachUserPolicy",
            "PutUserPolicy", "CreateAccessKey", "UpdateAccessKey", "GetCredentialReport",
            "AuthorizeSecurityGroupIngress", "DeleteSecurityGroup",
        }
        since = datetime.now(timezone.utc) - timedelta(minutes=10)
        try:
            client = self._client()
            events = []
            for event_name in list(SUSPICIOUS_EVENTS)[:5]:  # limit API calls
                resp = await asyncio.to_thread(
                    client.lookup_events,
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                    StartTime=since,
                    MaxResults=20,
                )
                for ev in resp.get("Events", []):
                    events.append({
                        "id": ev.get("EventId"),
                        "event_name": ev.get("EventName"),
                        "event_time": ev.get("EventTime").isoformat() if ev.get("EventTime") else None,
                        "username": ev.get("Username"),
                        "source_ip": ev.get("SourceIPAddress"),
                        "aws_region": ev.get("AwsRegion"),
                        "resources": ev.get("Resources", []),
                        "cloud_trail_event": ev.get("CloudTrailEvent"),
                    })
            logger.info("cloudtrail.pull fetched %d events", len(events))
            return events
        except Exception as e:
            logger.warning("cloudtrail.pull failed: %s", e)
            return []
