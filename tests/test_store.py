import json
import stat
import tempfile
import unittest
from pathlib import Path

from argus.errors import ValidationError
from argus.store import AssessmentStore


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = AssessmentStore(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_create_load_list(self):
        assessment = self.store.create("demo target")
        self.assertEqual(len(assessment.id), 32)
        loaded = self.store.load(assessment.id)
        self.assertEqual(loaded.name, "demo target")
        self.assertEqual(self.store.list()[0]["id"], assessment.id)

    def test_rejects_bad_ids(self):
        for bad in ["../../etc", "", "ABC", "0" * 31, "g" * 32]:
            with self.assertRaises(ValidationError):
                self.store.load(bad)
        with self.assertRaises(ValidationError):
            self.store.load("0" * 32)

    def test_permissions(self):
        assessment = self.store.create("perm")
        directory = self.store.assessments_dir / assessment.id
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((directory / "assessment.json").stat().st_mode), 0o600)
        self.store.append_event(assessment.id, "x", {"a": 1})
        self.assertEqual(stat.S_IMODE((directory / "events.jsonl").stat().st_mode), 0o600)

    def test_evidence_names_cannot_escape(self):
        assessment = self.store.create("paths")
        path = self.store.evidence_path(assessment.id, "../../etc/passwd")
        self.assertEqual(path.parent.name, "evidence")
        self.assertNotIn("..", path.name)
        with self.assertRaises(ValidationError):
            self.store.evidence_path(assessment.id, "..")

    def test_events_are_redacted(self):
        assessment = self.store.create("events")
        self.store.append_event(
            assessment.id,
            "request",
            {"token": "supersecret", "note": "password=hunter2", "ok": "visible"},
        )
        raw = (self.store.assessments_dir / assessment.id / "events.jsonl").read_text()
        self.assertNotIn("supersecret", raw)
        self.assertNotIn("hunter2", raw)
        self.assertIn("visible", raw)
        parsed = json.loads(raw.strip())
        self.assertEqual(parsed["action"], "request")

    def test_sensitive_event_drops_detail(self):
        assessment = self.store.create("sensitive")
        self.store.append_event(assessment.id, "login", {"password": "hunter2"}, sensitive=True)
        raw = (self.store.assessments_dir / assessment.id / "events.jsonl").read_text()
        self.assertNotIn("hunter2", raw)
        self.assertEqual(json.loads(raw.strip())["detail"], {})


if __name__ == "__main__":
    unittest.main()
