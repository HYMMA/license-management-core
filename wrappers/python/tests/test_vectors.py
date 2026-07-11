"""Vector-driven compatibility tests: the wrapper must verify exactly what
the license server signs (tests/vectors/*.json) and reject tampered tokens,
matching the C test suite case for case."""
import json
import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hymmalm
from hymmalm import LicenseError, LicenseErrorCode, LicenseStatus

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
VECTOR_FILES = ["vectors.json", "vectors-eddsa.json"]

STATUS_BY_NAME = {
    "Unknown": LicenseStatus.UNKNOWN,
    "Expired": LicenseStatus.EXPIRED,
    "Valid": LicenseStatus.VALID,
    "ValidTrial": LicenseStatus.VALID_TRIAL,
    "InvalidTrial": LicenseStatus.INVALID_TRIAL,
    "ReceiptExpired": LicenseStatus.RECEIPT_EXPIRED,
    "ReceiptUnregistered": LicenseStatus.RECEIPT_UNREGISTERED,
}


def load(name):
    with open(os.path.join(REPO, "tests", "vectors", name)) as f:
        return json.load(f)


def jwks_of(vec):
    keys = [vec[k] for k in ("RsaJwk", "EcJwk", "EdJwk") if k in vec]
    return json.dumps(keys)


def parse_now(case):
    s = case.get("NowUtc")
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


class VectorTests(unittest.TestCase):
    def test_all_vector_cases(self):
        for fname in VECTOR_FILES:
            vec = load(fname)
            jwks = jwks_of(vec)
            for case in vec["Cases"]:
                with self.subTest(file=fname, case=case["Name"]):
                    if case.get("Valid"):
                        status = hymmalm.verify(case["Jws"], jwks,
                                                now=parse_now(case))
                        if "ExpectedStatus" in case:
                            self.assertEqual(
                                status, STATUS_BY_NAME[case["ExpectedStatus"]])
                    else:
                        with self.assertRaises(LicenseError) as ctx:
                            hymmalm.verify(case["Jws"], jwks,
                                           now=parse_now(case))
                        self.assertIn(ctx.exception.code,
                                      (LicenseErrorCode.SIGNATURE_INVALID,
                                       LicenseErrorCode.MALFORMED_INPUT))

    def test_product_and_machine_binding(self):
        vec = load("vectors.json")
        jwks = jwks_of(vec)
        case = next(c for c in vec["Cases"] if c["Name"] == "rs256-trial-valid")
        now = parse_now(case)
        mac = "KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG"

        self.assertEqual(
            hymmalm.verify(case["Jws"], jwks, "PRD_01KWWPEPM0N070BDAHJ7G09RGV",
                           mac, now),
            LicenseStatus.VALID_TRIAL)

        with self.assertRaises(LicenseError) as ctx:
            hymmalm.verify(case["Jws"], jwks, "PRD_SOMETHINGELSE", mac, now)
        self.assertEqual(ctx.exception.code, LicenseErrorCode.PRODUCT_MISMATCH)

        with self.assertRaises(LicenseError) as ctx:
            hymmalm.verify(case["Jws"], jwks,
                           "PRD_01KWWPEPM0N070BDAHJ7G09RGV", "WRONGMACHINE", now)
        self.assertEqual(ctx.exception.code, LicenseErrorCode.COMPUTER_MISMATCH)

    def test_machine_identity(self):
        self.assertEqual(len(hymmalm.machine_id()), 52)
        self.assertTrue(hymmalm.machine_name())

    def test_error_names(self):
        err = LicenseError(int(LicenseErrorCode.SIGNATURE_INVALID))
        self.assertIn("signature", str(err))


if __name__ == "__main__":
    unittest.main()
