import json
import tempfile
import unittest
from pathlib import Path

from argus.config import Config
from argus.models import Endpoint
from argus.orchestrator import Orchestrator, _redact_record
from argus.store import AssessmentStore
from argus.traffic.barrel_backend import BarrelBackend
from argus.traffic.correlate import ActionWindow, correlate, windows_from_events
from argus.traffic.inventory import build_inventory, normalize_path
from argus.traffic.models import TrafficRecord

DEVICES = "List of devices attached\nemulator-5554\tdevice product:sdk model:Pixel\n"

ENTRIES = [
    {
        "id": 1,
        "started": 1_000,
        "method": "GET",
        "url": "https://api.example.com/v1/users/42?token=abc123",
        "host": "api.example.com",
        "path": "/v1/users/42",
        "scheme": "https",
        "status": 200,
        "state": "complete",
        "error": None,
        "tls": True,
        "content_type": "application/json",
        "duration_ms": 50,
        "req_headers": [
            ["Authorization", "Bearer abcdefghijkl"],
            ["Accept", "application/json"],
        ],
        "resp_headers": [["Set-Cookie", "session=xyz"]],
        "req_body": None,
        "resp_body": '{"user": 1}',
        "req_body_len": 0,
        "resp_body_len": 11,
        "req_body_truncated": False,
        "resp_body_truncated": False,
        "req_body_b64": False,
        "resp_body_b64": False,
    },
    {
        "id": 2,
        "started": 2_000,
        "method": "POST",
        "url": "https://api.example.com/v1/orders",
        "host": "api.example.com",
        "path": "/v1/orders",
        "scheme": "https",
        "status": 201,
        "state": "complete",
        "error": None,
        "tls": True,
        "content_type": "application/json",
        "duration_ms": 80,
        "req_headers": [["Content-Type", "application/json"]],
        "resp_headers": [],
        "req_body": '{"card": "4111111111111111"}',
        "resp_body": "{}",
        "req_body_len": 30,
        "resp_body_len": 2,
        "req_body_truncated": False,
        "resp_body_truncated": False,
        "req_body_b64": False,
        "resp_body_b64": False,
    },
    {
        "id": 3,
        "started": 3_000,
        "method": "GET",
        "url": "https://api.example.com/v1/users/7",
        "host": "api.example.com",
        "path": "/v1/users/7",
        "scheme": "https",
        "status": 404,
        "state": "complete",
        "error": None,
        "tls": True,
        "content_type": "application/json",
        "duration_ms": 20,
        "req_headers": [],
        "resp_headers": [],
        "req_body": None,
        "resp_body": None,
        "req_body_len": 0,
        "resp_body_len": 0,
        "req_body_truncated": False,
        "resp_body_truncated": False,
        "req_body_b64": False,
        "resp_body_b64": False,
    },
]


class FakeBarrel:
    def __init__(self, entries=None):
        self.entries = entries or ENTRIES
        self.calls = []

    async def list_devices(self):
        return DEVICES

    async def traffic_start(self):
        self.calls.append(("start",))
        return "proxy started"

    async def traffic_status_json(self):
        return json.dumps(
            {
                "running": True,
                "port": 8888,
                "ca_path": "/tmp/barrel-ca.pem",
                "total": len(self.entries),
                "entries": len(self.entries),
                "routes": [],
            }
        )

    async def traffic_entries_json(self, limit=100, entry_id=None, include_bodies=None):
        if entry_id is not None:
            for entry in self.entries:
                if entry["id"] == entry_id:
                    return json.dumps(entry)
            raise AssertionError("unknown entry")
        return json.dumps(self.entries[-limit:])

    async def traffic_route_device(self, device):
        self.calls.append(("route", device))
        return f"routed {device}"

    async def traffic_unroute_device(self, device):
        self.calls.append(("unroute", device))
        return f"unrouted {device}"

    async def traffic_stop(self):
        self.calls.append(("stop",))
        return "stopped"

    async def traffic_ensure_ca(self):
        return "CA at /tmp/barrel-ca.pem"

    async def cert_install(self, device, path, method="user"):
        self.calls.append(("cert", device, path, method))
        return f"installed {method} on {device}"


class InventoryTests(unittest.TestCase):
    def test_normalize_path(self):
        self.assertEqual(normalize_path("/v1/users/42"), "/v1/users/{id}")
        self.assertEqual(
            normalize_path("/v1/users/123e4567-e89b-12d3-a456-426614174000"),
            "/v1/users/{uuid}",
        )
        self.assertEqual(normalize_path("/v1/users/deadbeefdeadbeef"), "/v1/users/{id}")
        self.assertEqual(normalize_path("/"), "/")
        self.assertEqual(normalize_path("/v1/users/me"), "/v1/users/me")

    def test_inventory_dedupes_and_tags(self):
        records = [TrafficRecord.model_validate(entry) for entry in ENTRIES]
        inventory = build_inventory(records)
        keys = {endpoint.key for endpoint in inventory}
        self.assertIn("GET https://api.example.com/v1/users/{id}", keys)
        self.assertIn("POST https://api.example.com/v1/orders", keys)
        self.assertEqual(len(inventory), 2)

        users = next(e for e in inventory if e.method == "GET")
        self.assertTrue(users.auth)
        self.assertEqual(users.status_codes, [200, 404])
        self.assertEqual(users.sample_ids, [1, 3])
        self.assertIn("token", users.query_params)
        self.assertIn("account", users.sensitive_tags)
        self.assertIn("authentication", users.sensitive_tags)
        self.assertEqual(users.first_seen, 1_000)
        self.assertEqual(users.last_seen, 3_000)

        orders = next(e for e in inventory if e.method == "POST")
        self.assertFalse(orders.auth)
        self.assertIn("transaction", orders.sensitive_tags)

    def test_skips_connect(self):
        record = TrafficRecord.model_validate(
            {**ENTRIES[0], "id": 9, "method": "CONNECT", "url": "api.example.com:443"}
        )
        self.assertEqual(build_inventory([record]), [])


class CorrelateTests(unittest.TestCase):
    def test_windows_and_mapping(self):
        events = [
            {"ts": "2026-11-20T10:00:00+00:00", "action": "ui_tap"},
            {"ts": "2026-11-20T10:00:03+00:00", "action": "ui_tap_node"},
        ]
        windows = windows_from_events(events)
        self.assertEqual(len(windows), 2)
        self.assertEqual(windows[0].started_ms, 1795168800000)
        self.assertEqual(windows[0].ended_ms, 1795168803000)

        records = [
            TrafficRecord.model_validate({**ENTRIES[0], "started": 1795168800500}),
            TrafficRecord.model_validate({**ENTRIES[1], "started": 1795168802500}),
            TrafficRecord.model_validate({**ENTRIES[2], "started": 1795168804000}),
        ]
        mapped = correlate(records, windows)
        self.assertEqual(mapped[0]["record_ids"], [1, 2])
        self.assertEqual(mapped[1]["record_ids"], [3])
        self.assertEqual(mapped[0]["confidence"], "inferred")

    def test_no_windows(self):
        record = TrafficRecord.model_validate(ENTRIES[0])
        self.assertEqual(correlate([record], []), [])


class RedactRecordTests(unittest.TestCase):
    def test_headers_and_url(self):
        record = TrafficRecord.model_validate(ENTRIES[0])
        redacted = _redact_record(record, ())
        headers = dict(redacted["req_headers"])
        self.assertEqual(headers["Authorization"], "***")
        self.assertEqual(headers["Accept"], "application/json")
        self.assertEqual(dict(redacted["resp_headers"])["Set-Cookie"], "***")
        self.assertNotIn("abc123", redacted["url"])
        self.assertIn("token=***", redacted["url"])


class BarrelBackendTests(unittest.IsolatedAsyncioTestCase):
    async def test_entries_and_install_ca(self):
        client = FakeBarrel()
        backend = BarrelBackend(client)
        records = await backend.entries(2)
        self.assertEqual([record.id for record in records], [2, 3])
        one = await backend.entry(1)
        self.assertEqual(one.url, ENTRIES[0]["url"])
        output = await backend.install_ca("emulator-5554", "user")
        self.assertIn("emulator-5554", output)
        self.assertIn(("cert", "emulator-5554", "/tmp/barrel-ca.pem", "user"), client.calls)


class CaptureFlowTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = Config(barrel_bin=Path("/bin/true"), data_dir=self.root / "data")
        self.store = AssessmentStore(self.config.data_dir)
        self.barrel = FakeBarrel()
        self.orch = Orchestrator(self.config, self.store, self.barrel)

    def tearDown(self):
        self.tmp.cleanup()

    async def _ready(self):
        assessment = await self.orch.create("traffic")
        await self.orch.configure(
            assessment.id, package="com.example", device="emulator-5554"
        )
        return await self.orch.start(assessment.id)

    async def test_capture_flow(self):
        assessment = await self._ready()
        started = await self.orch.capture_start(
            assessment.id, install_ca=True, ca_method="user"
        )
        self.assertTrue(started["ok"])
        self.assertTrue(started["ca_installed"])
        self.assertEqual(started["status"]["port"], 8888)
        self.assertIn(("route", "emulator-5554"), self.barrel.calls)

        saved = self.store.load(assessment.id)
        self.assertTrue(saved.capture_active)
        self.assertEqual(saved.capture_port, 8888)

        entries = await self.orch.capture_entries(assessment.id)
        self.assertEqual(entries["count"], 3)
        self.assertNotIn("abc123", entries["entries"][0]["url"])

        stopped = await self.orch.capture_stop(assessment.id)
        self.assertTrue(stopped["ok"])
        self.assertEqual(stopped["entries"], 3)
        self.assertEqual(stopped["endpoints"], 2)
        self.assertEqual(stopped["warnings"], [])
        evidence = self.store._dir(assessment.id) / "evidence"
        self.assertTrue((evidence / stopped["traffic"]).is_file())
        self.assertTrue((evidence / stopped["inventory"]).is_file())

        saved = self.store.load(assessment.id)
        self.assertFalse(saved.capture_active)
        self.assertEqual(len(saved.endpoints), 2)
        self.assertIsInstance(saved.endpoints[0], Endpoint)

        inventory = await self.orch.endpoint_inventory(assessment.id)
        self.assertEqual(inventory["count"], 2)

        again = await self.orch.capture_stop(assessment.id)
        self.assertTrue(again["already_stopped"])

        actions = [event["action"] for event in self.orch.events(assessment.id)]
        self.assertIn("capture_started", actions)
        self.assertIn("capture_stopped", actions)

    async def test_correlate_marks_inferred(self):
        assessment = await self._ready()
        result = await self.orch.capture_correlate(assessment.id)
        self.assertEqual(result["count"], 3)
        self.assertEqual(result["confidence"], "inferred")
        self.assertEqual(result["windows"], [])


if __name__ == "__main__":
    unittest.main()
