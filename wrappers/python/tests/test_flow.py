"""End-to-end client flow against a local mock of the license API.

The mock serves the checked-in signed vectors and a fixed `GET DateTime`
(2026-07-10T00:00:00Z). HLM_TIMESYNC=off makes the native client resolve its
trusted evaluation time from that endpoint, so the expected statuses are
deterministic regardless of the real clock — and the server-time fallback of
the clock-tamper cascade is exercised on every call.
"""
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hymmalm import (LicenseClient, LicenseError, LicenseErrorCode,
                     LicenseImportOutcome, LicenseStatus, NetworkFailure,
                     SignedFormat)

os.environ["HLM_TIMESYNC"] = "off"

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
PRODUCT = "PRD_01KWWPEPM0N070BDAHJ7G09RGV"
MACHINE = "KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG"

with open(os.path.join(REPO, "tests", "vectors", "vectors.json")) as f:
    VEC = json.load(f)
CASES = {c["Name"]: c["Jws"] for c in VEC["Cases"]}
JWKS = json.dumps([VEC["RsaJwk"]])


class MockApi(BaseHTTPRequestHandler):
    server_version = "MockLicenseApi/1"

    def log_message(self, *args):
        pass

    def _send(self, code, body=""):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        st = self.server.state
        if st.get("fail_status"):
            self._send(st["fail_status"], st.get("fail_body", "{}"))
        elif self.path.startswith("/api/DateTime"):
            self._send(200, '"2026-07-10T00:00:00Z"')
        elif self.path.startswith("/api/computer"):
            self._send(200, '{"id":"PC_01KWVTRYM7AXBT1V56M2N3E3AB"}')
        elif self.path.startswith("/api/license"):
            self._send(200, CASES[st["license_case"]])
        else:
            self._send(404, "{}")

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        st = self.server.state
        if st.get("fail_status"):
            self._send(st["fail_status"], st.get("fail_body", "{}"))
        else:
            self._send(201, "{}")

    def do_PATCH(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        req = json.loads(body)
        st = self.server.state
        st["license_case"] = ("rs256-paid-valid" if req.get("Code") is not None
                              else "rs256-receipt-unregistered")
        self._send(204)


class FlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), MockApi)
        cls.srv.state = {"license_case": "rs256-trial-valid"}
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}/api/"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.srv.state.clear()
        self.srv.state["license_case"] = "rs256-trial-valid"

    def client(self, base=None, path=None):
        return LicenseClient(product_id=PRODUCT, client_api_key="PUB_test",
                             jwks_json=JWKS, base_url=base or self.base,
                             fmt=SignedFormat.RS256, machine_id=MACHINE,
                             machine_name="SHOP-FLOOR-01", license_path=path)

    def test_trial_activate_cache_deactivate(self):
        lic_path = os.path.join(os.path.dirname(__file__), "flow-test.lic")
        if os.path.exists(lic_path):
            os.remove(lic_path)
        try:
            with self.client(path=lic_path) as c:
                self.assertEqual(c.check(), LicenseStatus.VALID_TRIAL)
                self.assertEqual(c.license_id,
                                 "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0")
                self.assertEqual(c.product_name, "CADshift Nesting")
                self.assertIsNotNone(c.trial_end)

                self.assertEqual(c.activate("RCPT-CODE-1234"),
                                 LicenseStatus.VALID)
                self.assertEqual(c.buyer_email, "jane@example.com")
                self.assertEqual(c.metadata("seat"), "floor-1")
                self.assertTrue(c.live_mode)
                self.assertIsNotNone(c.expires)

            # a fresh client on a dead URL must surface the cached license
            with self.client(base="http://127.0.0.1:1/api/",
                             path=lic_path) as c:
                self.assertEqual(c.check(), LicenseStatus.VALID)

            with self.client(path=lic_path) as c:
                self.assertEqual(c.check(), LicenseStatus.VALID)
                self.assertEqual(c.deactivate(),
                                 LicenseStatus.RECEIPT_UNREGISTERED)
        finally:
            if os.path.exists(lic_path):
                os.remove(lic_path)

    def test_invalid_api_key(self):
        self.srv.state["fail_status"] = 401
        with self.client() as c:
            with self.assertRaises(LicenseError) as ctx:
                c.check()
            self.assertEqual(ctx.exception.code,
                             LicenseErrorCode.INVALID_API_KEY)

    def test_trial_quota_detail(self):
        self.srv.state["fail_status"] = 402
        self.srv.state["fail_body"] = json.dumps(
            {"error": "trial_quota",
             "detail": "Active-trial quota exhausted for this vendor."})
        with self.client() as c:
            with self.assertRaises(LicenseError) as ctx:
                c.check()
            self.assertEqual(ctx.exception.code,
                             LicenseErrorCode.TRIAL_QUOTA_EXCEEDED)
            self.assertIn("quota", ctx.exception.detail)

    def test_offline_without_cache_reports_network_failure(self):
        with self.client(base="http://127.0.0.1:1/api/") as c:
            with self.assertRaises(LicenseError) as ctx:
                c.check()
            self.assertEqual(ctx.exception.code,
                             LicenseErrorCode.NETWORK_FAILURE)
            # ...and says what failed, naming the host to allow
            self.assertEqual(ctx.exception.network_failure,
                             NetworkFailure.CONNECTION)
            self.assertEqual(c.last_network_failure, NetworkFailure.CONNECTION)
            self.assertTrue(ctx.exception.detail.startswith(
                "Could not connect to 127.0.0.1."))

    def test_proxy_407_reports_proxy(self):
        self.srv.state["fail_status"] = 407
        with self.client() as c:
            with self.assertRaises(LicenseError) as ctx:
                c.check()
            self.assertEqual(ctx.exception.code,
                             LicenseErrorCode.NETWORK_FAILURE)
            self.assertEqual(ctx.exception.network_failure,
                             NetworkFailure.PROXY)
            self.assertIn("proxy refused the connection to 127.0.0.1",
                          ctx.exception.detail)


class ImportTests(unittest.TestCase):
    """Installing a license file by hand: never touches the network."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cache = os.path.join(self.dir, "cache.lic")
        with open(self.cache, "w") as f:
            f.write(CASES["rs256-trial-valid"])

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def client(self, machine=MACHINE, product=PRODUCT):
        return LicenseClient(product_id=product, client_api_key="PUB_test",
                             jwks_json=JWKS, base_url="http://127.0.0.1:1/api/",
                             machine_id=machine, machine_name="SHOP-FLOOR-01",
                             license_path=self.cache)

    def cached(self):
        with open(self.cache) as f:
            return f.read()

    def test_genuine_file_installs(self):
        src = os.path.join(self.dir, "downloaded.lic")
        with open(src, "w", encoding="utf-8-sig") as f:  # BOM, as browsers save
            f.write(CASES["rs256-paid-valid"] + "\n")
        with self.client() as c:
            self.assertEqual(c.license_path, self.cache)
            r = c.import_license_file(src)
            self.assertTrue(r.succeeded)
            self.assertEqual(r.outcome, LicenseImportOutcome.INSTALLED)
            self.assertEqual(r.message, "License file installed.")
            self.assertEqual(r.installed_path, self.cache)
            self.assertEqual(c.license_id, "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0")
        self.assertEqual(self.cached(), CASES["rs256-paid-valid"])

    def assert_refused(self, client, document, outcome, message_part):
        with client as c:
            r = c.import_license(document)
            self.assertEqual(r.outcome, outcome)
            self.assertFalse(r.succeeded)
            self.assertIn(message_part, r.message)
        self.assertEqual(self.cached(), CASES["rs256-trial-valid"])

    def test_tampered_refused_and_cache_untouched(self):
        self.assert_refused(self.client(), CASES["rs256-tampered-payload"],
                            LicenseImportOutcome.SIGNATURE_INVALID,
                            "or it has been changed")

    def test_other_product_refused(self):
        self.assert_refused(self.client(product="PRD_OTHER"),
                            CASES["rs256-paid-valid"],
                            LicenseImportOutcome.WRONG_PRODUCT,
                            "This license file is for CADshift Nesting, "
                            "not this one.")

    def test_other_computer_refused(self):
        self.assert_refused(self.client(machine="OTHER" + "0" * 47),
                            CASES["rs256-paid-valid"],
                            LicenseImportOutcome.WRONG_COMPUTER,
                            "for the computer SHOP-FLOOR-01")

    def test_garbage_refused(self):
        self.assert_refused(self.client(), "definitely not a license",
                            LicenseImportOutcome.NOT_A_LICENSE_FILE,
                            "That isn't a license file.")

    def test_unreadable_file(self):
        with self.client() as c:
            r = c.import_license_file(os.path.join(self.dir, "missing.lic"))
            self.assertEqual(r.outcome, LicenseImportOutcome.NOT_A_LICENSE_FILE)
            self.assertTrue(r.message.startswith("The file could not be read"))
        self.assertEqual(self.cached(), CASES["rs256-trial-valid"])


if __name__ == "__main__":
    unittest.main()
