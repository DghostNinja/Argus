"""Report renderers: Markdown, canonical JSON and findings CSV.

Pure functions over the assessment model; the orchestrator supplies evidence
excerpts. Evidence files are redacted before they are stored, so excerpts are
safe to embed. Findings are ordered confirmed first, then by severity, so a
report never ranks a lead above a proven issue.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Iterable

from .models import Assessment, Finding, SEVERITIES

SEV_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}
STATUS_RANK = {"confirmed": 0, "potential": 1, "rejected": 2}

REPORT_FILES = {"md": "report.md", "json": "report.json", "csv": "findings.csv"}


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Confirmed before potential before rejected; then severity; then newest."""
    return sorted(
        findings,
        key=lambda finding: (
            STATUS_RANK.get(finding.status, 3),
            SEV_RANK.get(finding.severity, len(SEVERITIES)),
            finding.updated_at,
        ),
        reverse=False,
    )


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def status_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {"confirmed": 0, "potential": 0, "rejected": 0}
    for finding in findings:
        counts[finding.status] = counts.get(finding.status, 0) + 1
    return counts


def render_markdown(
    assessment: Assessment,
    excerpts: dict[str, str],
    generated_at: str,
) -> str:
    """Full assessment report: summary, findings by status, coverage, limits."""
    findings = sort_findings(assessment.findings)
    by_status: dict[str, list[Finding]] = {
        "confirmed": [],
        "potential": [],
        "rejected": [],
    }
    for finding in findings:
        by_status.setdefault(finding.status, []).append(finding)

    lines: list[str] = []
    lines.append(f"# Argus Assessment Report — {assessment.name}")
    lines.append("")
    lines.append(f"- Assessment: `{assessment.id}`")
    lines.append(f"- Package: {assessment.target.package or '(not set)'}")
    lines.append(f"- Device: {assessment.device or assessment.target.device or '(not set)'}")
    lines.append(f"- State: {assessment.state.value}")
    lines.append(f"- Generated: {generated_at}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Findings |")
    lines.append("| --- | --- |")
    counts = severity_counts(assessment.findings)
    for severity in SEVERITIES:
        label = severity.capitalize()
        lines.append(f"| {label} | {counts.get(severity, 0)} |")
    lines.append("")
    status = status_counts(assessment.findings)
    lines.append(
        f"- Confirmed: **{status['confirmed']}** · "
        f"Potential: **{status['potential']}** · "
        f"Rejected: **{status['rejected']}**"
    )
    lines.append(f"- Endpoints inventoried: **{len(assessment.endpoints)}**")
    lines.append("")

    sections = (
        ("confirmed", "Confirmed findings"),
        ("potential", "Potential findings (leads, not yet reproduced)"),
        ("rejected", "Rejected findings"),
    )
    for key, heading in sections:
        lines.append(f"## {heading}")
        lines.append("")
        block = by_status.get(key, [])
        if not block:
            lines.append("_None._")
            lines.append("")
            continue
        for index, finding in enumerate(block, start=1):
            lines.append(
                f"### {index}. [{finding.severity.upper()}] {finding.title}"
            )
            lines.append("")
            lines.append(f"- Id: `{finding.id}`")
            lines.append(f"- Confidence: {finding.confidence}")
            lines.append(f"- Status: {finding.status}")
            if finding.endpoint:
                lines.append(f"- Endpoint: {finding.endpoint}")
            lines.append(f"- Updated: {finding.updated_at}")
            lines.append("")
            if finding.description:
                lines.append(finding.description)
                lines.append("")
            if finding.evidence:
                lines.append("**Evidence:**")
                lines.append("")
                for name in finding.evidence:
                    lines.append(f"- `{name}` — {excerpts.get(name, 'stored evidence file')}")
                lines.append("")

    lines.append("## Endpoint coverage")
    lines.append("")
    if not assessment.endpoints:
        lines.append("_No traffic was captured; nothing could be inventoried._")
        lines.append("")
    else:
        lines.append("| Method | Host | Path | Auth | Status codes | Findings |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        finding_endpoints = {
            finding.endpoint for finding in assessment.findings if finding.endpoint
        }
        for endpoint in sorted(
            assessment.endpoints, key=lambda item: (item.method, item.host, item.path)
        ):
            hit = "yes" if endpoint.key in finding_endpoints else "0"
            codes = (
                ", ".join(str(code) for code in endpoint.status_codes) or "-"
            )
            auth = "yes" if endpoint.auth else "no"
            lines.append(
                f"| {endpoint.method} | {endpoint.host} | {endpoint.path} "
                f"| {auth} | {codes} | {hit} |"
            )
        lines.append("")

    untested = sum(
        1
        for endpoint in assessment.endpoints
        if endpoint.key not in {f.endpoint for f in assessment.findings if f.endpoint}
    )
    lines.append("## Methodology and limits")
    lines.append("")
    lines.append(
        "- Scope: every replayed request was limited to the configured "
        "`allowed_hosts`; public hosts required `allow_production`."
    )
    lines.append(
        "- Correlation between UI actions and traffic is timing-inferred, "
        "not proven."
    )
    lines.append(
        "- Auth headers used for replay live in process memory only; evidence "
        "files store redacted traffic."
    )
    lines.append(
        f"- {untested} of {len(assessment.endpoints)} inventoried endpoints have "
        "no finding recorded against them: absence of a finding is not proof "
        "the endpoint is safe."
    )
    if not assessment.findings:
        lines.append(
            "- No findings were recorded; this report documents coverage only."
        )
    lines.append("")
    return "\n".join(lines)


def render_csv(findings: Iterable[Finding]) -> str:
    """Flat findings export for spreadsheets and tracking systems."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "id",
            "status",
            "severity",
            "confidence",
            "endpoint",
            "title",
            "description",
            "evidence",
            "created_at",
            "updated_at",
        ]
    )
    for finding in sort_findings(findings):
        writer.writerow(
            [
                finding.id,
                finding.status,
                finding.severity,
                finding.confidence,
                finding.endpoint or "",
                finding.title,
                finding.description.replace("\n", " ").strip(),
                ";".join(finding.evidence),
                finding.created_at,
                finding.updated_at,
            ]
        )
    return buffer.getvalue()


def render_json(assessment: Assessment, generated_at: str) -> dict:
    """Canonical machine-readable output: meta, summary, findings, coverage."""
    findings = sort_findings(assessment.findings)
    finding_endpoints = {
        finding.endpoint for finding in assessment.findings if finding.endpoint
    }
    return {
        "meta": {
            "assessment_id": assessment.id,
            "name": assessment.name,
            "state": assessment.state.value,
            "package": assessment.target.package,
            "device": assessment.device or assessment.target.device,
            "allowed_hosts": assessment.target.allowed_hosts,
            "allow_production": assessment.target.allow_production,
            "generated_at": generated_at,
        },
        "summary": {
            "severity_counts": severity_counts(assessment.findings),
            "status_counts": status_counts(assessment.findings),
            "endpoints": len(assessment.endpoints),
            "endpoints_without_findings": sum(
                1 for endpoint in assessment.endpoints
                if endpoint.key not in finding_endpoints
            ),
        },
        "findings": [finding.model_dump(mode="json") for finding in findings],
        "endpoints": [endpoint.model_dump(mode="json") for endpoint in assessment.endpoints],
    }
