import json
import tempfile
import unittest
from pathlib import Path

import httpx

from argus.config import Config
from argus.errors import ReplayError, StateError, ValidationError
from argus.orchestrator import Orchestrator
from argus.replay import (
    ReplayEngine,
    check_method,
    compare_replay_payloads,
    host_in_scope,
    is_local_host,
)
from argus.store import AssessmentStore
from argus.traffic.models import TrafficRecord

DEVICES = "List of devices attached\nemulator-5554\tdevice model:Pixel\n"


class FakeBarrel:
    def __init__(self):
        self.devices = DEVICES

    async def list_devices(self):
        return self.devices


def make_handler():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/secure":
            if request.headers.get("authorization") != "Bearer live-token-123":
                return httpx.Response(401, json={"error": "unauthorized"})
            return httpx.Response(200, json={"ok": True, "role": "user"})
        if path == "/base":
            return httpx.Response(200, json={"role": "user", "balance": 10})
        if path == "/var":
            return httpx.Response(200, json={"role": "admin", "balance": 10})
        if path == "/plain":
            return httpx.Response(200, text="hello world")
        return httpx.Response(404, json={"error": "not found"})

    return handler


class HelperTests(unittest.TestCase):
    def test_is_local_host(self):
        self.assertTrue(is_local_host("localhost"))
        self.assertTrue(is_local_host("api.internal"))
        self.assertTrue(is_local_host("127.0.0.1"))
        self.assertTrue(is_local_host("10.0.0.5"))
        self.assertTrue(is_local_host("192.168.1.148"))
        self.assertFalse(is_local_host("api.example.com"))
        self.assertFalse(is_local_host(""))

    def test_host_in_scope(self):
        self.assertTrue(host_in_scope("api.internal", ["api.internal"]))
        self.assertTrue(host_in_scope("API.internal", ["api.internal"]))
        self.assertTrue(host_in_scope("a.b.test.com", ["*.b.test.com"]))
        self.assertFalse(host_in_scope("b.test.com", ["*.b.test.com"]))
        self.assertFalse(host_in_scope("evil.com", ["api.internal"]))
        self.assertTrue(host_in_scope("anything.io", ["*"]))
        self.assertTrue(host_in_scope("api.internal", ["api.internal:8443"]))

    def test_check_method(self):
        self.assertEqual(check_method("get"), "GET")
        self.assertEqual(check_method("POST"), "POST")
        with self.assertRaises(ValidationError):
            check_method("DELETE")
        with self.assertRaises(ValidationError):
            check_method("TRACE")

    def test_compare_identical(self):
        payload = {
            "response": {"status": 200, "content_type": "application/json", "body": '{"a":1}'}
        }
        diff = compare_replay_payloads(payload, payload)
        self.assertFalse(diff["changed"])
        self.assertEqual(diff["verdict"], "no difference")

    def test_compare_status_and_json(self):
        base = {
            "response": {"status": 200, "content_type": "application/json", "body": '{"role":"user"}'}
        }
        var = {
            "response": {"status": 200, "content_type": "application/json", "body": '{"role":"admin"}'}
        }
        diff = compare_replay_payloads(base, var)
        self.assertTrue(diff["changed"])
        self.assertEqual(diff["json_diff"][0]["path"], "$.role")
        var_status = {"response": {"status": 403, "content_type": "application/json", "body": '{"role":"admin"}'}}
        diff = compare_replay_payloads(base, var_status)
        self.assertTrue(diff["status_changed"])
        self.assertIn("status 200 -> 403", diff["notes"])


class OrchestratorTestingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = Config(barrel_bin=Path("/bin/true"), data_dir=self.root / "data")
        self.store = AssessmentStore(self.config.data_dir)
        self.barrel = FakeBarrel()
        self.transport = httpx.MockTransport(make_handler())
        self.replay = ReplayEngine(self.config, transport=self.transport)
        self.orch = Orchestrator(self.config, self.store, self.barrel, replay=self.replay)

    def tearDown(self):
        self.tmp.cleanup()

    async def _testing(self, allowed=None, allow_production=False):
        assessment = await self.orch.create("phase4")
        assessment = await self.orch.configure(
            assessment.id,
            package="com.example",
            device="emulator-5554",
            allowed_hosts=allowed or ["api.internal"],
            allow_production=allow_production,
        )
        assessment = await self.orch.start(assessment.id)
        assessment = await self.orch.testing_begin(assessment.id)
        return assessment

    async def test_testing_begin_requires_device(self):
        assessment = await self.orch.create("gates")
        await self.orch.configure(assessment.id, package="com.example")
        with self.assertRaises(StateError):
            await self.orch.testing_begin(assessment.id)
        await self.orch.start(assessment.id)
        assessment = await self.orch.testing_begin(assessment.id)
        self.assertEqual(assessment.state.value, "testing")
        again = await self.orch.testing_begin(assessment.id)
        self.assertEqual(again.state.value, "testing")

    async def test_replay_refused_before_testing(self):
        assessment = await self.orch.create("early")
        await self.orch.configure(
            assessment.id, package="com.example", allowed_hosts=["api.internal"]
        )
        await self.orch.start(assessment.id)
        with self.assertRaises(StateError):
            await self.orch.replay_send(
                assessment.id, "GET", "https://api.internal/plain"
            )

    async def test_replay_scope_and_method_gates(self):
        assessment = await self._testing()
        with self.assertRaises(ValidationError):
            await self.orch.replay_send(
                assessment.id, "GET", "https://evil.test.com/x"
            )
        with self.assertRaises(ValidationError):
            await self.orch.replay_send(
                assessment.id, "DELETE", "https://api.internal/plain"
            )
        with self.assertRaises(ValidationError):
            await self.orch.replay_send(
                assessment.id, "GET", "ftp://api.internal/plain"
            )

    async def test_production_gate(self):
        assessment = await self._testing(
            allowed=["api.example.com"], allow_production=False
        )
        with self.assertRaises(ValidationError) as ctx:
            await self.orch.replay_send(
                assessment.id, "GET", "https://api.example.com/x"
            )
        self.assertIn("allow_production", str(ctx.exception))

        assessment = await self._testing(
            allowed=["api.example.com"], allow_production=True
        )
        result = await self.orch.replay_send(
            assessment.id, "GET", "https://api.example.com/x"
        )
        self.assertEqual(result["status"], 404)

    async def test_replay_writes_redacted_evidence(self):
        assessment = await self._testing()
        result = await self.orch.replay_send(
            assessment.id,
            "GET",
            "https://api.internal/v1/users/42",
            headers={"Authorization": "Bearer super-secret-value"},
        )
        self.assertEqual(result["status"], 404)
        self.assertEqual(result["request_headers"]["Authorization"], "***")
        raw = self.store.read_evidence(assessment.id, result["evidence"]).decode()
        self.assertNotIn("super-secret-value", raw)
        payload = json.loads(raw)
        self.assertEqual(payload["request"]["method"], "GET")
        self.assertEqual(payload["response"]["status"], 404)
        events = self.orch.events(assessment.id)
        self.assertIn("replay_sent", [e["action"] for e in events])
        self.assertNotIn("super-secret-value", str(events))

    async def test_auth_set_and_replay_merge(self):
        assessment = await self._testing()
        with self.assertRaises(ValidationError):
            await self.orch.auth_set(
                assessment.id, "api.internal", {"X-Custom": "nope"}
            )
        with self.assertRaises(ValidationError):
            await self.orch.auth_set(
                assessment.id, "evil.test.com", {"Authorization": "Bearer x"}
            )
        await self.orch.auth_set(
            assessment.id, "api.internal", {"Authorization": "Bearer live-token-123"}
        )
        denied = await self.orch.replay_send(
            assessment.id, "GET", "https://api.internal/secure", use_auth=False
        )
        self.assertEqual(denied["status"], 401)
        allowed = await self.orch.replay_send(
            assessment.id, "GET", "https://api.internal/secure"
        )
        self.assertEqual(allowed["status"], 200)
        self.assertTrue(allowed["auth_used"])
        events = str(self.orch.events(assessment.id))
        self.assertNotIn("live-token-123", events)
        raw = self.store.read_evidence(assessment.id, allowed["evidence"]).decode()
        self.assertNotIn("live-token-123", raw)

        cleared = await self.orch.auth_clear(assessment.id)
        self.assertEqual(cleared["cleared"], 1)
        after = await self.orch.replay_send(
            assessment.id, "GET", "https://api.internal/secure"
        )
        self.assertEqual(after["status"], 401)

    async def test_capture_snapshot_feeds_replay(self):
        assessment = await self._testing()
        record = TrafficRecord(
            id=1,
            started=0,
            method="GET",
            url="https://api.internal/secure",
            host="api.internal",
            req_headers=[("Authorization", "Bearer live-token-123")],
        )
        self.orch._snapshot_auth(assessment.id, [record])
        result = await self.orch.replay_send(
            assessment.id, "GET", "https://api.internal/secure"
        )
        self.assertEqual(result["status"], 200)

    async def test_replay_compare(self):
        assessment = await self._testing()
        base = await self.orch.replay_send(
            assessment.id, "GET", "https://api.internal/base"
        )
        var = await self.orch.replay_send(
            assessment.id, "GET", "https://api.internal/var"
        )
        diff = await self.orch.replay_compare(
            assessment.id, base["evidence"], var["evidence"]
        )
        self.assertTrue(diff["changed"])
        self.assertEqual(diff["json_diff"][0]["path"], "$.role")
        same = await self.orch.replay_send(
            assessment.id, "GET", "https://api.internal/base"
        )
        diff = await self.orch.replay_compare(
            assessment.id, base["evidence"], same["evidence"]
        )
        self.assertFalse(diff["changed"])
        with self.assertRaises(ValidationError):
            await self.orch.replay_compare(
                assessment.id, "traffic-x.json", same["evidence"]
            )

    async def test_finding_lifecycle(self):
        assessment = await self._testing()
        with self.assertRaises(ValidationError):
            await self.orch.finding_create(
                assessment.id,
                title="x",
                severity="urgent",
                confidence="low",
            )
        with self.assertRaises(ValidationError):
            await self.orch.finding_create(
                assessment.id,
                title="x",
                severity="low",
                confidence="low",
                evidence=["missing.json"],
            )
        replay = await self.orch.replay_send(
            assessment.id, "GET", "https://api.internal/secure"
        )
        finding = await self.orch.finding_create(
            assessment.id,
            title="IDOR on /secure",
            severity="high",
            confidence="medium",
            status="potential",
            endpoint="GET https://api.internal/secure",
            description="401 without auth, 200 with",
            evidence=[replay["evidence"]],
        )
        self.assertEqual(finding["status"], "potential")
        self.assertEqual(len(finding["id"]), 16)

        updated = await self.orch.finding_update(
            assessment.id, finding["id"], "confirmed", note="reproduced twice"
        )
        self.assertEqual(updated["status"], "confirmed")
        self.assertIn("reproduced twice", updated["description"])

        listed = self.orch.finding_list(assessment.id)
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["counts"]["confirmed"], 1)

        with self.assertRaises(ValidationError):
            await self.orch.finding_update(
                assessment.id, finding["id"], "definitely"
            )
        with self.assertRaises(ValidationError):
            await self.orch.finding_update(assessment.id, "nope", "confirmed")

    async def test_pause_blocks_replay(self):
        assessment = await self._testing()
        await self.orch.pause(assessment.id)
        with self.assertRaises(StateError):
            await self.orch.replay_send(
                assessment.id, "GET", "https://api.internal/plain"
            )
        with self.assertRaises(StateError):
            await self.orch.finding_create(
                assessment.id, title="t", severity="low", confidence="low"
            )
        await self.orch.resume(assessment.id)
        result = await self.orch.replay_send(
            assessment.id, "GET", "https://api.internal/plain"
        )
        self.assertEqual(result["status"], 200)

    async def test_replay_transport_failure_is_typed(self):
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("nope", request=request)

        orch = Orchestrator(
            self.config,
            self.store,
            self.barrel,
            replay=ReplayEngine(self.config, transport=httpx.MockTransport(down)),
        )
        assessment = await self._testing()
        with self.assertRaises(ReplayError):
            await orch.replay_send(
                assessment.id, "GET", "https://api.internal/plain"
            )


if __name__ == "__main__":
    unittest.main()
