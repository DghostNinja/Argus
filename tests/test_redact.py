import unittest

from argus.redact import redact_headers, redact_obj, redact_text


class RedactTests(unittest.TestCase):
    def test_headers(self):
        headers = {
            "Authorization": "Bearer abcdefghijklmnop",
            "Cookie": "session=1",
            "Content-Type": "application/json",
            "X-Api-Key": "secret-value",
        }
        out = redact_headers(headers)
        self.assertEqual(out["Authorization"], "***")
        self.assertEqual(out["Cookie"], "***")
        self.assertEqual(out["X-Api-Key"], "***")
        self.assertEqual(out["Content-Type"], "application/json")

    def test_bearer_and_jwt(self):
        text = "Authorization: Bearer abcdefghijklmnop and eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123"
        out = redact_text(text)
        self.assertNotIn("abcdefghijklmnop", out)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", out)

    def test_json_pairs(self):
        text = '{"password": "hunter2", "access_token":"abc", "user":"bob"}'
        out = redact_text(text)
        self.assertNotIn("hunter2", out)
        self.assertNotIn('"abc"', out)
        self.assertIn("bob", out)

    def test_nested_obj(self):
        out = redact_obj({"a": ["token=abc", {"password": "x"}], "ok": 1})
        self.assertNotIn("abc", str(out))
        self.assertNotIn("'x'", str(out))
        self.assertEqual(out["ok"], 1)

    def test_extra_patterns(self):
        out = redact_text("key is SECRETVALUE", extra_patterns=[r"SECRETVALUE"])
        self.assertEqual(out, "key is ***")


if __name__ == "__main__":
    unittest.main()
