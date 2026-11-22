import unittest

from argus.errors import ValidationError
from argus.explore.ui import best_node, find_nodes, parse_hierarchy

XML = """<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
  <node text="" resource-id="" class="android.widget.FrameLayout" package="com.example"
        content-desc="" clickable="false" enabled="true" bounds="[0,0][1080,1920]">
    <node text="Sign in" resource-id="com.example:id/title" class="android.widget.TextView"
          package="com.example" content-desc="" clickable="false" enabled="true"
          bounds="[100,200][980,300]" />
    <node text="Username" resource-id="com.example:id/user" class="android.widget.EditText"
          package="com.example" content-desc="" clickable="true" enabled="true" focusable="true"
          bounds="[100,400][980,500]" />
    <node text="Password" resource-id="com.example:id/pass" class="android.widget.EditText"
          package="com.example" content-desc="Password field" clickable="true" enabled="true"
          focusable="true" password="true" bounds="[100,600][980,700]" />
    <node text="LOGIN" resource-id="com.example:id/login" class="android.widget.Button"
          package="com.example" content-desc="" clickable="true" enabled="true"
          bounds="[100,800][980,900]" />
    <node text="Disabled" resource-id="com.example:id/off" class="android.widget.Button"
          package="com.example" content-desc="" clickable="true" enabled="false"
          bounds="[100,1000][980,1100]" />
  </node>
</hierarchy>
"""


class UiTests(unittest.TestCase):
    def test_parse_and_centers(self):
        nodes = parse_hierarchy(XML)
        self.assertEqual(len(nodes), 6)
        login = best_node(nodes, text="LOGIN")
        self.assertEqual(login.center, (540, 850))
        self.assertTrue(login.clickable)
        self.assertEqual(login.area, 880 * 100)

    def test_find_by_resource_id_and_desc(self):
        nodes = parse_hierarchy(XML)
        self.assertEqual(find_nodes(nodes, resource_id="id/user")[0].text, "Username")
        self.assertEqual(find_nodes(nodes, content_desc="password field")[0].text, "Password")
        self.assertTrue(find_nodes(nodes, text="Password")[0].password)

    def test_clickable_filter_and_exact(self):
        nodes = parse_hierarchy(XML)
        clickable = find_nodes(nodes, clickable=True)
        self.assertEqual(len(clickable), 4)
        self.assertEqual(find_nodes(nodes, text="sign", exact=True), [])
        self.assertEqual(len(find_nodes(nodes, text="Sign in", exact=True)), 1)

    def test_rank_prefers_clickable(self):
        nodes = parse_hierarchy(XML)
        match = find_nodes(nodes, text="Password")[0]
        self.assertTrue(match.clickable)

    def test_rejects_dtd_and_oversize(self):
        with self.assertRaises(ValidationError):
            parse_hierarchy("<!DOCTYPE x [<!ENTITY y 'z'>]><hierarchy/>")
        with self.assertRaises(ValidationError):
            parse_hierarchy("<hierarchy>" + " " * 100 + "</hierarchy>", max_bytes=10)

    def test_rejects_bad_xml(self):
        with self.assertRaises(ValidationError):
            parse_hierarchy("<hierarchy><node bounds='[0,0][1,1]'></hierarchy>")


if __name__ == "__main__":
    unittest.main()
