import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from argus.config import Config
from argus.errors import StateError, ValidationError
from argus.models import Endpoint, Finding
from argus.orchestrator import Orchestrator
from argus.report import (
    render_csv,
    render_json,
    render_markdown,
    severity_counts,
    sort_findings,
    status_counts,
)
from argus.store import AssessmentStore


def make_finding(**kwargs) -> Finding:
    defaults = {
        "id": "a" * 16,
        "title": "Broken access control",
        "severity": "high",
        "confidence": "high",
        "status": "confirmed",
        "endpoint": "GET https://api.internal/v1/users/{id}",
        "description": "User A read user B's record.",
        "evidence": ["replay-x.json"],
        "created_at": "2026-11-25T10:00:00+00:00",
        "updated_at": "2026-11-25T10:00:00+00:00",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


class RenderTests(unittest.TestCase):
    def test_sort_orders_status_then_severity(self):
        findings = [
            make_finding(id="b" * 16, status="potential", severity="critical"),
            make_finding(id="c" * 16, status="confirmed", severity="low"),
            make_finding(id="d" * 16, status="rejected", severity="critical"),
            make_finding(id="a" * 16, status="confirmed", severity="critical"),
        ]
        ordered = sort_findings(findings)
        self.assertEqual(
            [f.status for f in ordered],
            ["confirmed", "confirmed", "potential", "rejected"],
        )
        self.assertEqual(ordered[0].severity, "critical")
        self.assertEqual(ordered[1].severity, "low")

    def test_counts(self):
        findings = [
            make_finding(severity="critical", status="confirmed"),
            make_finding(id="b" * 16, severity="low", status="potential"),
            make_finding(id="c" * 16, severity="low", status="potential"),
        ]
        self.assertEqual(severity_counts(findings)["critical"], 1)
        self.assertEqual(severity_counts(findings)["low"], 2)
        self.assertEqual(status_counts(findings)["potential"], 2)

    def _assessment(self):
        from argus.models import Assessment, AssessmentState, Target

        return Assessment(
            id="f" * 32,
            name="lab",
            state=AssessmentState.REPORTED,
            target=Target(
                package="com.example",
                allowed_hosts=["api.internal"],
            ),
            device="emulator-5554",
            findings=[
                make_finding(),
                make_finding(
                    id="b" * 16,
                    title="Leaky debug endpoint",
                    severity="info",
                    status="potential",
                    evidence=[],
                ),
            ],
            endpoints=[
                Endpoint(
                    key="GET https://api.internal/v1/users/{id}",
                    method="GET",
                    scheme="https",
                    host="api.internal",
                    path="/v1/users/{id}",
                    status_codes=[200, 401],
                    auth=True,
                ),
                Endpoint(
                    key="POST https://api.internal/v1/login",
                    method="POST",
                    scheme="https",
                    host="api.internal",
                    path="/v1/login",
                    status_codes=[200],
                ),
            ],
        )

    def test_markdown_report(self):
        assessment = self._assessment()
        text = render_markdown(
            assessment,
            {"replay-x.json": "GET https://api.internal/v1/users/42 -> 401"},
            "2026-11-25T12:00:00+00:00",
        )
        self.assertIn("# Argus Assessment Report — lab", text)
        self.assertIn("## Summary", text)
        self.assertIn("| High | 1 |", text)
        self.assertIn("Confirmed: **1**", text)
        self.assertIn("## Confirmed findings", text)
        self.assertIn("### 1. [HIGH] Broken access control", text)
        self.assertIn("GET https://api.internal/v1/users/42 -> 401", text)
        self.assertIn("## Potential findings", text)
        self.assertIn("Leaky debug endpoint", text)
        self.assertIn("## Endpoint coverage", text)
        self.assertIn("| GET | api.internal | /v1/users/{id} | yes | 200, 401 | yes |", text)
        self.assertIn("| POST | api.internal | /v1/login | no | 200 | 0 |", text)
        self.assertIn("absence of a finding is not proof", text)
        self.assertIn("1 of 2 inventoried endpoints have", text)

    def test_markdown_empty(self):
        from argus.models import Assessment, AssessmentState, Target

        assessment = Assessment(
            id="e" * 32,
            name="empty",
            state=AssessmentState.TESTING,
            target=Target(),
        )
        text = render_markdown(assessment, {}, "2026-11-25T12:00:00+00:00")
        self.assertIn("_None._", text)
        self.assertIn("No findings were recorded", text)
        self.assertIn("nothing could be inventoried", text)

    def test_csv_export(self):
        findings = [
            make_finding(status="potential", severity="low"),
            make_finding(id="b" * 16, status="confirmed", severity="critical"),
        ]
        rows = list(csv.reader(io.StringIO(render_csv(findings))))
        self.assertEqual(
            rows[0],
            [
                "id", "status", "severity", "confidence", "endpoint",
                "title", "description", "evidence", "created_at", "updated_at",
            ],
        )
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[1][2], "critical")
        self.assertEqual(rows[2][2], "low")
        self.assertEqual(rows[1][7], "replay-x.json")

    def test_json_export(self):
        assessment = self._assessment()
        payload = render_json(assessment, "2026-11-25T12:00:00+00:00")
        self.assertEqual(payload["meta"]["assessment_id"], "f" * 32)
        self.assertEqual(payload["meta"]["allowed_hosts"], ["api.internal"])
        self.assertEqual(payload["summary"]["status_counts"]["confirmed"], 1)
        self.assertEqual(payload["summary"]["endpoints"], 2)
        self.assertEqual(payload["summary"]["endpoints_without_findings"], 1)
        self.assertEqual(payload["findings"][0]["severity"], "high")
        self.assertNotIn("steps", payload)


class FakeBarrel:
    devices = "List of devices attached\nemulator-5554\tdevice model:Pixel\n"

    async def list_devices(self):
        return self.devices


class ReportToolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = Config(barrel_bin=Path("/bin/true"), data_dir=self.root / "data")
        self.store = AssessmentStore(self.config.data_dir)
        self.orch = Orchestrator(self.config, self.store, FakeBarrel())

    def tearDown(self):
        self.tmp.cleanup()

    async def _testing(self):
        assessment = await self.orch.create("phase5")
        assessment = await self.orch.configure(
            assessment.id,
            package="com.example",
            allowed_hosts=["api.internal"],
        )
        assessment = await self.orch.start(assessment.id)
        return await self.orch.testing_begin(assessment.id)

    async def test_report_refused_before_testing(self):
        assessment = await self.orch.create("early")
        await self.orch.configure(assessment.id, package="com.example")
        with self.assertRaises(StateError):
            await self.orch.report_generate(assessment.id)

    async def test_report_writes_all_formats_and_transitions(self):
        assessment = await self._testing()
        result = await self.orch.report_generate(assessment.id)
        self.assertTrue(result["ok"])
        self.assertTrue(result["transitioned"])
        self.assertEqual(result["state"], "reported")
        names = sorted(item["name"] for item in result["files"])
        self.assertEqual(names, ["findings.csv", "report.json", "report.md"])
        for name in names:
            path = self.store.evidence_path(assessment.id, name)
            self.assertTrue(path.is_file())
            self.assertGreater(path.stat().st_size, 0)
        stored = self.store.load(assessment.id)
        self.assertEqual(stored.state.value, "reported")
        actions = [
            event["action"]
            for event in self.store.events(assessment.id, limit=10)
        ]
        self.assertIn("report_generated", actions)

    async def test_report_format_subset_and_validation(self):
        assessment = await self._testing()
        result = await self.orch.report_generate(assessment.id, formats=["md"])
        self.assertEqual([item["name"] for item in result["files"]], ["report.md"])
        with self.assertRaises(ValidationError):
            await self.orch.report_generate(
                assessment.id, formats=["html"]
            )
        with self.assertRaises(ValidationError):
            await self.orch.report_generate(assessment.id, formats=[])

    async def test_report_regenerates_from_reported(self):
        assessment = await self._testing()
        await self.orch.report_generate(assessment.id)
        again = await self.orch.report_generate(assessment.id, formats=["json"])
        self.assertFalse(again["transitioned"])
        self.assertEqual(again["state"], "reported")

    async def test_findings_still_allowed_after_report(self):
        assessment = await self._testing()
        await self.orch.report_generate(assessment.id)
        finding = await self.orch.finding_create(
            assessment.id,
            title="Late finding",
            severity="low",
            confidence="medium",
        )
        self.assertEqual(finding["status"], "potential")
        updated = await self.orch.finding_update(
            assessment.id, finding["id"], "confirmed"
        )
        self.assertEqual(updated["status"], "confirmed")
        result = await self.orch.report_generate(assessment.id, formats=["md"])
        self.assertTrue(result["ok"])
        text = self.store.read_evidence(assessment.id, "report.md").decode("utf-8")
        self.assertIn("Late finding", text)
        self.assertIn("Confirmed: **1**", text)

    async def test_report_embeds_replay_evidence_excerpt(self):
        assessment = await self._testing()
        payload = {
            "ts": "2026-11-25T10:00:00+00:00",
            "request": {
                "method": "GET",
                "url": "https://api.internal/v1/users/42",
                "headers": [],
                "body": "",
            },
            "response": {"status": 401, "content_type": "application/json"},
        }
        name = "replay-20261125T100000Z-abcdef.json"
        self.store.write_evidence(
            assessment.id, name, json.dumps(payload).encode("utf-8")
        )
        await self.orch.finding_create(
            assessment.id,
            title="IDOR probe",
            severity="high",
            confidence="high",
            status="confirmed",
            endpoint="GET https://api.internal/v1/users/{id}",
            evidence=[name],
        )
        await self.orch.report_generate(assessment.id, formats=["md"])
        text = self.store.read_evidence(assessment.id, "report.md").decode("utf-8")
        self.assertIn(
            "GET https://api.internal/v1/users/42 -> 401", text
        )

    async def test_report_survives_missing_evidence(self):
        assessment = await self._testing()
        await self.orch.finding_create(
            assessment.id,
            title="No evidence",
            severity="info",
            confidence="low",
            evidence=[],
        )
        result = await self.orch.report_generate(assessment.id, formats=["md"])
        self.assertTrue(result["ok"])
        text = self.store.read_evidence(assessment.id, "report.md").decode("utf-8")
        self.assertIn("No evidence", text)


if __name__ == "__main__":
    unittest.main()
