"""Tests for certbot_dns_selectel_api_v2.dns_selectel_api_v2."""

import json
import tempfile
import unittest

import requests_mock
from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_test_common import DOMAIN

FAKE_ACCOUNT = "expected_account_id"
FAKE_PROJECT = "expected_project_name"
FAKE_USER = "expected_remote_user"
FAKE_PW = "expected_password"
FAKE_AUTH_ENDPOINT = "mock://auth_endpoint"
FAKE_API_ENDPOINT = "mock://api_endpoint"
FAKE_TOKEN = "expected_token"

ZONE_ID = "ed350b64-3c0a-4adf-b2e2-a0b54b9d8b42"
SUBZONE_ID = "6453f393-ab75-4fb6-b608-3774fef11108"
RRSET_ID = "b1b0dfcd-9a0f-4a3d-9d19-5b2e39a3b8b2"

VALIDATION = "fake-validation-value"
VALIDATION_NAME = f"_acme-challenge.{DOMAIN}"


def zones_response(*zones):
    return json.dumps({
        "count": len(zones),
        "next_offset": 0,
        "result": [{"id": zone_id, "name": name} for zone_id, name in zones],
    })


def rrsets_response(*rrsets):
    return json.dumps({
        "count": len(rrsets),
        "next_offset": 0,
        "result": list(rrsets),
    })


class SelectelClientTest(unittest.TestCase):
    def setUp(self):
        from certbot_dns_selectel_api_v2.dns_selectel_api_v2 import \
            _SelectelClient
        with tempfile.NamedTemporaryFile("w+") as f:
            f.write(f"""
            auth_endpoint = "{FAKE_AUTH_ENDPOINT}"
            api_endpoint = "{FAKE_API_ENDPOINT}"
            account_id = "{FAKE_ACCOUNT}"
            username = "{FAKE_USER}"
            password = "{FAKE_PW}"
            project_name = "{FAKE_PROJECT}"
            """)
            f.seek(0)
            credentials = dns_common.CredentialsConfiguration(f.name)
        self.adapter = requests_mock.Adapter()
        self.client = _SelectelClient(credentials)
        self.client.session.mount("mock://", self.adapter)
        self._register_auth()

    def _register_auth(self):
        def auth_request_matcher(req):
            expected_data = {
                "auth": {
                    "identity": {
                        "methods": ["password"],
                        "password": {
                            "user": {
                                "name": FAKE_USER,
                                "domain": {"name": FAKE_ACCOUNT},
                                "password": FAKE_PW}}},
                    "scope": {
                        "project": {
                            "name": FAKE_PROJECT,
                            "domain": {"name": FAKE_ACCOUNT}}}}}
            return json.loads(req.text) == expected_data

        self.adapter.register_uri(
            "POST", f"{FAKE_AUTH_ENDPOINT}/identity/v3/auth/tokens",
            headers={"X-Subject-Token": FAKE_TOKEN},
            additional_matcher=auth_request_matcher,
        )

    @staticmethod
    def _authenticated(req):
        return req.headers.get("X-Auth-Token") == FAKE_TOKEN

    def _register_zones(self, *zones):
        self.adapter.register_uri(
            "GET", f"{FAKE_API_ENDPOINT}/domains/v2/zones",
            additional_matcher=self._authenticated,
            text=zones_response(*zones),
        )

    def test_get_zone_id_by_domain(self):
        self._register_zones(
            (ZONE_ID, f"{DOMAIN}."),
            (SUBZONE_ID, "example.org."),
        )
        self.assertEqual(self.client.get_zone_id_by_domain(DOMAIN), ZONE_ID)

    def test_get_zone_id_by_domain_for_subdomain(self):
        self._register_zones((ZONE_ID, f"{DOMAIN}."))
        self.assertEqual(
            self.client.get_zone_id_by_domain(f"sub.{DOMAIN}"), ZONE_ID)

    def test_get_zone_id_by_domain_prefers_most_specific_zone(self):
        """A delegated subzone must win over its parent regardless of order."""
        self._register_zones(
            (ZONE_ID, f"{DOMAIN}."),
            (SUBZONE_ID, f"sub.{DOMAIN}."),
        )
        self.assertEqual(
            self.client.get_zone_id_by_domain(f"sub.{DOMAIN}"), SUBZONE_ID)

    def test_get_zone_id_by_domain_respects_label_boundary(self):
        """notexample.com must not match the example.com zone."""
        self._register_zones((ZONE_ID, f"{DOMAIN}."))
        with self.assertRaises(errors.PluginError):
            self.client.get_zone_id_by_domain(f"not{DOMAIN}")

    def test_get_zone_id_by_domain_not_found(self):
        self._register_zones((SUBZONE_ID, "example.org."))
        with self.assertRaises(errors.PluginError):
            self.client.get_zone_id_by_domain(DOMAIN)

    def test_add_record(self):
        def matcher(req):
            data = json.loads(req.text)
            return (self._authenticated(req)
                    and data["name"] == VALIDATION_NAME
                    and data["type"] == "TXT"
                    and data["ttl"] == 60
                    and data["records"] == [
                        {"content": f'"{VALIDATION}"', "disabled": False}])

        self.adapter.register_uri(
            "POST", f"{FAKE_API_ENDPOINT}/domains/v2/zones/{ZONE_ID}/rrset",
            additional_matcher=matcher,
            text=json.dumps({"id": RRSET_ID}),
        )
        self.assertEqual(
            self.client.add_record(ZONE_ID, VALIDATION_NAME, VALIDATION, 60),
            RRSET_ID)

    def test_update_record_keeps_existing_values(self):
        """The wildcard + apex pair shares one rrset with two values."""
        rrset = {
            "id": RRSET_ID,
            "name": f"{VALIDATION_NAME}.",
            "type": "TXT",
            "records": [{"content": '"other-value"', "disabled": False}],
        }
        captured = {}

        def matcher(req):
            captured["records"] = json.loads(req.text)["records"]
            return self._authenticated(req)

        self.adapter.register_uri(
            "PATCH",
            f"{FAKE_API_ENDPOINT}/domains/v2/zones/{ZONE_ID}"
            f"/rrset/{RRSET_ID}",
            additional_matcher=matcher,
            text=json.dumps(rrset),
        )
        self.client.update_record(
            ZONE_ID, rrset, VALIDATION_NAME, VALIDATION, 60)
        self.assertEqual(captured["records"], [
            {"content": '"other-value"', "disabled": False},
            {"content": f'"{VALIDATION}"', "disabled": False},
        ])

    def test_remove_record_drops_only_own_value(self):
        rrset = {
            "id": RRSET_ID,
            "name": f"{VALIDATION_NAME}.",
            "type": "TXT",
            "records": [
                {"content": '"other-value"', "disabled": False},
                {"content": f'"{VALIDATION}"', "disabled": False},
            ],
        }
        captured = {}

        def patch_matcher(req):
            captured["records"] = json.loads(req.text)["records"]
            return self._authenticated(req)

        url = (f"{FAKE_API_ENDPOINT}/domains/v2/zones/{ZONE_ID}"
               f"/rrset/{RRSET_ID}")
        self.adapter.register_uri(
            "GET", url,
            additional_matcher=self._authenticated,
            text=json.dumps(rrset),
        )
        self.adapter.register_uri(
            "PATCH", url,
            additional_matcher=patch_matcher,
            text=json.dumps(rrset),
        )
        self.client.remove_record(
            ZONE_ID, RRSET_ID, VALIDATION_NAME, VALIDATION, 60)
        self.assertEqual(captured["records"],
                         [{"content": '"other-value"', "disabled": False}])

    def test_remove_record_deletes_empty_rrset(self):
        rrset = {
            "id": RRSET_ID,
            "name": f"{VALIDATION_NAME}.",
            "type": "TXT",
            "records": [{"content": f'"{VALIDATION}"', "disabled": False}],
        }
        url = (f"{FAKE_API_ENDPOINT}/domains/v2/zones/{ZONE_ID}"
               f"/rrset/{RRSET_ID}")
        self.adapter.register_uri(
            "GET", url,
            additional_matcher=self._authenticated,
            text=json.dumps(rrset),
        )
        deleted = self.adapter.register_uri(
            "DELETE", url,
            additional_matcher=self._authenticated,
            status_code=204, text="",
        )
        self.client.remove_record(
            ZONE_ID, RRSET_ID, VALIDATION_NAME, VALIDATION, 60)
        self.assertEqual(deleted.call_count, 1)

    def test_remove_record_tolerates_missing_rrset(self):
        """A 404 on cleanup must not abort the certbot run."""
        url = (f"{FAKE_API_ENDPOINT}/domains/v2/zones/{ZONE_ID}"
               f"/rrset/{RRSET_ID}")
        self.adapter.register_uri(
            "GET", url,
            additional_matcher=self._authenticated,
            status_code=404, text='{"error": "rrset_not_found"}',
        )
        self.assertIsNone(self.client.remove_record(
            ZONE_ID, RRSET_ID, VALIDATION_NAME, VALIDATION, 60))

    def test_auth_failure_reports_keystone_error(self):
        """Keystone nests the error in an object, breaking join()."""
        self.adapter.register_uri(
            "POST", f"{FAKE_AUTH_ENDPOINT}/identity/v3/auth/tokens",
            status_code=401,
            text=json.dumps({"error": {
                "code": 401,
                "title": "Unauthorized",
                "message": "The request you have made requires "
                           "authentication.",
            }}),
        )
        with self.assertRaises(errors.PluginError) as ctx:
            self.client.get_zone_id_by_domain(DOMAIN)
        message = str(ctx.exception)
        self.assertIn("401", message)
        self.assertIn("Unauthorized", message)
        self.assertIn("requires authentication", message)
        self.assertIn("account_id", message)

    def test_error_response_with_flat_error_fields(self):
        """The domains API uses flat string fields instead."""
        self.adapter.register_uri(
            "GET", f"{FAKE_API_ENDPOINT}/domains/v2/zones",
            additional_matcher=self._authenticated,
            status_code=403,
            text=json.dumps({"error": "forbidden",
                             "description": "no access to the zone"}),
        )
        with self.assertRaises(errors.PluginError) as ctx:
            self.client.get_zone_id_by_domain(DOMAIN)
        message = str(ctx.exception)
        self.assertIn("forbidden", message)
        self.assertIn("no access to the zone", message)

    def test_error_response_without_known_fields(self):
        self.adapter.register_uri(
            "GET", f"{FAKE_API_ENDPOINT}/domains/v2/zones",
            additional_matcher=self._authenticated,
            status_code=500,
            text=json.dumps({"unexpected": "shape"}),
        )
        with self.assertRaises(errors.PluginError) as ctx:
            self.client.get_zone_id_by_domain(DOMAIN)
        self.assertIn("500", str(ctx.exception))

    def test_error_response_with_non_json_body(self):
        self.adapter.register_uri(
            "GET", f"{FAKE_API_ENDPOINT}/domains/v2/zones",
            additional_matcher=self._authenticated,
            status_code=502, text="<html>bad gateway</html>",
        )
        with self.assertRaises(errors.PluginError) as ctx:
            self.client.get_zone_id_by_domain(DOMAIN)
        self.assertIn("bad gateway", str(ctx.exception))

    def test_get_zone_rrset_by_name(self):
        rrset = {
            "id": RRSET_ID,
            "name": f"{VALIDATION_NAME}.",
            "type": "TXT",
            "records": [],
        }
        self.adapter.register_uri(
            "GET", f"{FAKE_API_ENDPOINT}/domains/v2/zones/{ZONE_ID}/rrset",
            additional_matcher=self._authenticated,
            text=rrsets_response(
                {"id": "other", "name": f"{VALIDATION_NAME}.", "type": "A",
                 "records": []},
                rrset,
            ),
        )
        self.assertEqual(
            self.client.get_zone_rrset_by_name(ZONE_ID, VALIDATION_NAME),
            rrset)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
