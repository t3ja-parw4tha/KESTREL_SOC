"""Compliance report generation helpers."""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from zipfile import ZIP_DEFLATED, ZipFile

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import AuditLog, ComplianceReportArtifact, EvidenceAttachment
from app.models.alert import Alert, AlertStatus

ALLOWED_FRAMEWORKS = {"soc2", "iso27001", "pci-dss"}


def _checksum_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sign_checksum(checksum: str) -> str:
    secret = get_settings().secret_key.get_secret_value().encode("utf-8")
    return hmac.new(secret, checksum.encode("utf-8"), hashlib.sha256).hexdigest()


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_minimal_pdf(lines: list[str]) -> bytes:
    text_parts = []
    start_y = 760
    for idx, line in enumerate(lines[:45]):
        y = start_y - (idx * 14)
        text_parts.append(f"1 0 0 1 50 {y} Tm ({_escape_pdf_text(line)}) Tj")
    stream = "BT /F1 10 Tf " + " ".join(text_parts) + " ET"
    stream_bytes = stream.encode("latin-1", errors="ignore")

    objects: list[bytes] = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
    objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
    objects.append(
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n"
    )
    objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
    objects.append(f"5 0 obj << /Length {len(stream_bytes)} >> stream\n".encode("ascii") + stream_bytes + b"\nendstream endobj\n")

    header = b"%PDF-1.4\n"
    body = b""
    offsets = [0]
    cursor = len(header)
    for obj in objects:
        offsets.append(cursor)
        body += obj
        cursor += len(obj)
    xref_offset = len(header) + len(body)
    xref = [f"xref\n0 {len(objects) + 1}\n", "0000000000 65535 f \n"]
    for off in offsets[1:]:
        xref.append(f"{off:010d} 00000 n \n")
    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    )
    return header + body + "".join(xref).encode("ascii") + trailer.encode("ascii")


def _build_report_csv(report: dict) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["section", "key", "value"])
    writer.writerow(["meta", "framework", report.get("framework", "")])
    writer.writerow(["meta", "period_days", report.get("period_days", "")])
    writer.writerow(["meta", "generated_at", report.get("generated_at", "")])

    for key, value in (report.get("kpis") or {}).items():
        writer.writerow(["kpi", key, value])

    for row in (report.get("evidence") or []):
        writer.writerow(["evidence", str(row.get("type", "")), row.get("count", 0)])

    return output.getvalue().encode("utf-8")


def _build_report_pdf(report: dict, report_id: str, checksum: str) -> bytes:
    kpis = report.get("kpis") or {}
    lines = [
        "KESTREL Compliance Evidence Report",
        f"Report ID: {report_id}",
        f"Framework: {report.get('framework', '')}",
        f"Lookback Days: {report.get('period_days', '')}",
        f"Generated At: {report.get('generated_at', '')}",
        f"Report Checksum (sha256): {checksum}",
        "",
        "KPIs",
        f"alerts_total: {kpis.get('alerts_total', 0)}",
        f"alerts_resolved: {kpis.get('alerts_resolved', 0)}",
        f"evidence_items: {kpis.get('evidence_items', 0)}",
        f"audit_events: {kpis.get('audit_events', 0)}",
        f"resolution_rate: {kpis.get('resolution_rate', 0.0)}",
        "",
        "Controls Covered",
    ]
    for control in report.get("controls_covered") or []:
        lines.append(f"- {control}")
    return _build_minimal_pdf(lines)


async def build_compliance_artifact_bundle(
    db: AsyncSession,
    framework: str,
    days: int,
    created_by: str | None,
) -> dict:
    """Generate immutable signed compliance artifact bundle and persist metadata."""
    report = await build_compliance_report(db, framework, days)
    report_json = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    report_checksum = _checksum_sha256(report_json)
    signature = _sign_checksum(report_checksum)
    report_id = str(uuid.uuid4())

    pdf_bytes = _build_report_pdf(report, report_id, report_checksum)
    csv_bytes = _build_report_csv(report)
    manifest = {
        "report_id": report_id,
        "framework": report.get("framework"),
        "period_days": report.get("period_days"),
        "generated_at": report.get("generated_at"),
        "checksum_algorithm": "sha256",
        "report_checksum": report_checksum,
        "signature_algorithm": "hmac-sha256",
        "signature": signature,
        "artifacts": {
            "report_pdf": f"kestrel-{framework}-report-{report_id}.pdf",
            "report_csv": f"kestrel-{framework}-report-{report_id}.csv",
            "report_json": f"kestrel-{framework}-report-{report_id}.json",
        },
    }
    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")

    bundle_io = io.BytesIO()
    bundle_name = f"kestrel-{framework}-report-{report_id}.zip"
    with ZipFile(bundle_io, mode="w", compression=ZIP_DEFLATED) as zf:
        zf.writestr(f"kestrel-{framework}-report-{report_id}.pdf", pdf_bytes)
        zf.writestr(f"kestrel-{framework}-report-{report_id}.csv", csv_bytes)
        zf.writestr(f"kestrel-{framework}-report-{report_id}.json", report_json)
        zf.writestr("manifest.json", manifest_bytes)

    db.add(
        ComplianceReportArtifact(
            report_id=report_id,
            framework=framework,
            period_days=days,
            report_checksum=report_checksum,
            signature=signature,
            artifact_name=bundle_name,
            created_by=created_by,
        )
    )
    await db.commit()

    return {
        "bundle_name": bundle_name,
        "bundle_bytes": bundle_io.getvalue(),
        "report_id": report_id,
        "report_checksum": report_checksum,
        "signature": signature,
    }


async def build_compliance_report(db: AsyncSession, framework: str, days: int) -> dict:
    """Build compliance evidence summary for a framework and lookback window."""
    fw = framework.lower()
    if fw not in ALLOWED_FRAMEWORKS:
        raise ValueError(f"Unsupported framework: {framework}")

    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    total_alerts_r = await db.execute(select(func.count()).select_from(Alert).where(Alert.created_at >= since))
    resolved_alerts_r = await db.execute(
        select(func.count()).select_from(Alert).where(Alert.created_at >= since, Alert.status == AlertStatus.RESOLVED)
    )
    evidence_r = await db.execute(
        select(func.count()).select_from(EvidenceAttachment).where(EvidenceAttachment.created_at >= since)
    )
    audit_r = await db.execute(
        select(func.count()).select_from(AuditLog).where(AuditLog.timestamp >= since)
    )

    total_alerts = total_alerts_r.scalar() or 0
    resolved_alerts = resolved_alerts_r.scalar() or 0
    evidence_items = evidence_r.scalar() or 0
    audit_events = audit_r.scalar() or 0

    controls = {
        "soc2": ["CC6.1", "CC6.2", "CC7.2", "CC7.3"],
        "iso27001": ["A.5", "A.8", "A.12", "A.16"],
        "pci-dss": ["10.2", "10.6", "11.4", "12.10"],
    }[fw]

    return {
        "framework": fw,
        "period_days": days,
        "generated_at": now.isoformat(),
        "kpis": {
            "alerts_total": total_alerts,
            "alerts_resolved": resolved_alerts,
            "evidence_items": evidence_items,
            "audit_events": audit_events,
            "resolution_rate": round((resolved_alerts / total_alerts) * 100, 1) if total_alerts else 0.0,
        },
        "controls_covered": controls,
        "evidence": [
            {"type": "alerts", "count": total_alerts},
            {"type": "resolved_alerts", "count": resolved_alerts},
            {"type": "attachments", "count": evidence_items},
            {"type": "audit_log_events", "count": audit_events},
        ],
    }
