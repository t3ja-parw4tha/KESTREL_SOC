"""AWS GuardDuty pull connector."""

import asyncio
import logging
from typing import Any

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class GuardDutyConnector(BaseConnector):
    """Pull GuardDuty findings via boto3."""

    @property
    def source_id(self) -> str:
        return "guardduty"

    @property
    def source_name(self) -> str:
        return "GuardDuty"

    def _client(self):  # type: ignore[no-untyped-def]
        import boto3

        settings = get_settings()
        region = (settings.aws_region or "us-east-1").strip()
        kw: dict[str, Any] = {"region_name": region}
        if settings.aws_access_key_id and settings.aws_secret_access_key.get_secret_value():
            kw["aws_access_key_id"] = settings.aws_access_key_id
            kw["aws_secret_access_key"] = settings.aws_secret_access_key.get_secret_value()
        return boto3.client("guardduty", **kw)

    async def test_connection(self) -> tuple[bool, str]:
        """List detectors to verify credentials."""
        try:
            client = self._client()
            client.list_detectors()
            return True, "OK"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        """List detectors, then list/get findings and return as event dicts."""
        try:
            client = self._client()
            detectors_resp = await asyncio.to_thread(client.list_detectors)
            detector_ids = detectors_resp.get("DetectorIds") or []
            if not detector_ids:
                logger.info("guardduty.pull no detectors")
                return []
        except Exception as e:
            logger.warning("guardduty.pull list_detectors failed: %s", e)
            return []

        events = []
        for det_id in detector_ids[:5]:  # limit detectors
            try:
                list_resp = await asyncio.to_thread(
                    client.list_findings,
                    DetectorId=det_id,
                    FindingCriteria={"Criterion": {"service.archived": {"Eq": ["false"]}}},
                    MaxResults=100,
                    SortCriteria={"AttributeName": "updatedAt", "OrderBy": "DESC"},
                )
                finding_ids = list_resp.get("FindingIds") or []
                if not finding_ids:
                    continue
                get_resp = await asyncio.to_thread(
                    client.get_findings,
                    DetectorId=det_id,
                    FindingIds=finding_ids,
                )
                findings = get_resp.get("Findings") or []
                for f in findings:
                    # Parser expects dict with title, severity, type, resource, service, etc.
                    ev = {
                        "id": f.get("Id"),
                        "title": f.get("Title"),
                        "type": f.get("Type"),
                        "severity": f.get("Severity"),
                        "updatedAt": f.get("UpdatedAt"),
                        "createdAt": f.get("CreatedAt"),
                        "resource": f.get("Resource"),
                        "service": f.get("Service"),
                        "accountId": f.get("AccountId"),
                    }
                    events.append(ev)
            except Exception as e:
                logger.warning("guardduty.pull detector %s failed: %s", det_id, e)
        logger.info("guardduty.pull fetched %d findings", len(events))
        return events
