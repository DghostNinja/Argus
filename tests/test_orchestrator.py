import hashlib
import tempfile
import unittest
from pathlib import Path

from argus.config import Config
from argus.errors import StateError, ValidationError
from argus.orchestrator import Orchestrator, parse_device_serials
from argus.store import AssessmentStore

XML = """<?xml version='1.0' encoding='UTF-8'?>
<hierarchy>
  <node text="Login" resource-id="app:id/login" class="android.widget.Button"
        package="com.example" content-desc="" clickable="true" enabled="true"
        bounds="[100,800][980,900]" />
  <node text="User" resource-id="app:id/user" class="android.widget.EditText"
        package="com.example" content-desc="" clickable="true" enabled="true"
        bounds="[100,400][980,500]" />
</hierarchy>
"""

DEVICES = "List of devices attached\nemulator-5554\tdevice product:sdk model:Pixel\n"


class FakeBarrel:
    def __init__(self, devices=DEVICES):
        self.devices = devices
        self.calls = []

    async def list_devices(self):
        return self.devices

    async def install_apk(self, path, device=None, **_kwargs):
        self.calls.append(("install", path, device))
        return "Performing Streamed Install\nSuccess"

    async def launch_package(self, package, device=None):
        self.calls.append(("launch", package, device))
        return "started"

    async def ui_dump(self, device=None):
        self.calls.append(("dump", device))
        return XML

    async def ui_tap(self, x, y, device=None):
        self.calls.append(("tap", x, y, device))
        return "tapped"

    async def ui_set_text(self, text, submit=False, device=None):
        self.calls.append(("text", text, submit, device))
        return "typed"

    async def ui_key(self, keyevent, device=None):
        self.calls.append(("key", keyevent, device))
        return "key"

    async def ui_swipe(self, x1, y1, x2, y2, duration_ms=300, device=None):
        self.calls.append(("swipe", x1, y1, x2, y2, duration_ms, device))
        return "swipe"

    async def screenshot(self, path, device=None):
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\n")
        return "saved"

    async def logcat_tail(self, lines=200, filter=None, device=None):
        return "token=supersecret\nFATAL EXCEPTION: main"

    async def app_stop(self, package, device=None):
        self.calls.append(("stop", package, device))
        return "stopped"


class DeviceParseTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_device_serials(DEVICES), ["emulator-5554"])
        self.assertEqual(parse_device_serials("List of devices attached\n"), [])
        self.assertEqual(
            parse_device_serials(
                "List of devices attached\na device x\nb offline\nc unauthorized\n"
            ),
            ["a"],
        )


class OrchestratorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = Config(barrel_bin=Path("/bin/true"), data_dir=self.root / "data")
        self.store = AssessmentStore(self.config.data_dir)
        self.barrel = FakeBarrel()
        self.orch = Orchestrator(self.config, self.store, self.barrel)
        self.apk = self.root / "target.apk"
        self.apk.write_bytes(b"PK\x03\x04fake apk")

    def tearDown(self):
        self.tmp.cleanup()

    async def _ready(self):
        assessment = await self.orch.create("demo")
        assessment = await self.orch.configure(
            assessment.id,
            package="com.example",
            apk_path=str(self.apk),
            device="emulator-5554",
            allowed_hosts=["API.example.com"],
        )
        assessment = await self.orch.start(assessment.id)
        return assessment

    async def test_full_phase2_flow(self):
        assessment = await self._ready()
        self.assertEqual(assessment.state.value, "device_ready")
        self.assertEqual(assessment.device, "emulator-5554")
        self.assertEqual(assessment.target.allowed_hosts, ["api.example.com"])
        self.assertEqual(
            assessment.target.apk_sha256,
            hashlib.sha256(self.apk.read_bytes()).hexdigest(),
        )

        await self.orch.install(assessment.id)
        self.assertEqual(self.store.load(assessment.id).state.value, "installed")
        await self.orch.launch(assessment.id)

        dump = await self.orch.ui_dump(assessment.id)
        self.assertEqual(dump["count"], 2)
        self.assertEqual(self.store.load(assessment.id).state.value, "explored")

        tapped = await self.orch.ui_tap_node(assessment.id, text="Login")
        self.assertEqual(tapped["tapped"], [540, 850])

        await self.orch.ui_text(assessment.id, "hunter2", sensitive=True)
        events = self.orch.events(assessment.id)
        self.assertNotIn("hunter2", str(events))

        shot = await self.orch.screenshot(assessment.id, "login")
        self.assertTrue(Path(shot["path"]).is_file())
        self.assertEqual(Path(shot["path"]).parent.name, "evidence")

        log = await self.orch.logcat(assessment.id)
        self.assertNotIn("supersecret", log["output"])

    async def test_pause_and_stop_block_actions(self):
        assessment = await self._ready()
        await self.orch.install(assessment.id)
        await self.orch.pause(assessment.id)
        with self.assertRaises(StateError):
            await self.orch.ui_tap(assessment.id, 10, 10)
        await self.orch.resume(assessment.id)
        await self.orch.ui_tap(assessment.id, 10, 10)
        await self.orch.stop(assessment.id)
        with self.assertRaises(StateError):
            await self.orch.ui_dump(assessment.id)

    async def test_rejects_injection_and_missing_inputs(self):
        assessment = await self.orch.create("bad")
        with self.assertRaises(ValidationError):
            await self.orch.configure(assessment.id, package="com.example; rm -rf /")
        with self.assertRaises(ValidationError):
            await self.orch.configure(assessment.id, apk_path="/nope/missing.apk")
        with self.assertRaises(ValidationError):
            await self.orch.configure(
                assessment.id, package="com.example", allowed_hosts=["evil host"]
            )
        with self.assertRaises(ValidationError):
            await self.orch.configure(assessment.id)

    async def test_multiple_devices_require_explicit_choice(self):
        self.barrel.devices = (
            "List of devices attached\n"
            "emulator-5554\tdevice model:A\n"
            "emulator-5556\tdevice model:B\n"
        )
        assessment = await self.orch.create("multi")
        assessment = await self.orch.configure(assessment.id, package="com.example")
        with self.assertRaises(StateError):
            await self.orch.start(assessment.id)
        assessment = await self.orch.configure(assessment.id, device="emulator-5556")
        assessment = await self.orch.start(assessment.id)
        self.assertEqual(assessment.device, "emulator-5556")

    async def test_start_without_device_fails(self):
        self.barrel.devices = "List of devices attached\n"
        assessment = await self.orch.create("nodevice")
        assessment = await self.orch.configure(assessment.id, package="com.example")
        with self.assertRaises(StateError):
            await self.orch.start(assessment.id)


if __name__ == "__main__":
    unittest.main()
