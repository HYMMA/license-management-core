package com.hymma.licensing;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static com.hymma.licensing.TestRunner.assertEquals;
import static com.hymma.licensing.TestRunner.assertTrue;
import static com.hymma.licensing.TestRunner.expectLicenseError;

/**
 * Vector-driven compatibility tests: the wrapper must verify exactly what the
 * license server signs (tests/vectors/*.json) and reject tampered tokens,
 * matching the C test suite and the Python wrapper case for case.
 */
final class VectorTests {

    static final String[] VECTOR_FILES = {"vectors.json", "vectors-eddsa.json"};

    static final Map<String, LicenseStatus> STATUS_BY_NAME = Map.of(
            "Unknown", LicenseStatus.UNKNOWN,
            "Expired", LicenseStatus.EXPIRED,
            "Valid", LicenseStatus.VALID,
            "ValidTrial", LicenseStatus.VALID_TRIAL,
            "InvalidTrial", LicenseStatus.INVALID_TRIAL,
            "ReceiptExpired", LicenseStatus.RECEIPT_EXPIRED,
            "ReceiptUnregistered", LicenseStatus.RECEIPT_UNREGISTERED);

    /** wrappers/java → repo root; overridable via -Dhlm.repo for odd cwd's. */
    static Path vectorsDir() {
        return Path.of(System.getProperty("hlm.repo", "../.."))
                .resolve("tests").resolve("vectors");
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> load(String name) throws Exception {
        String text = Files.readString(vectorsDir().resolve(name));
        return (Map<String, Object>) Json.parse(text);
    }

    /** JWKS for verify = JSON array of whichever JWKs the vector file has. */
    static String jwksOf(Map<String, Object> vec) {
        StringBuilder sb = new StringBuilder("[");
        for (String key : new String[]{"RsaJwk", "EcJwk", "EdJwk"}) {
            if (vec.containsKey(key)) {
                if (sb.length() > 1) {
                    sb.append(',');
                }
                sb.append(Json.write(vec.get(key)));
            }
        }
        return sb.append(']').toString();
    }

    static Instant parseNow(Map<String, Object> testCase) {
        String s = (String) testCase.get("NowUtc");
        return s == null ? null : Instant.parse(s);
    }

    @SuppressWarnings("unchecked")
    static void run(TestRunner t) throws Exception {
        // -- every case from both vector files ---------------------------- //
        for (String fname : VECTOR_FILES) {
            Map<String, Object> vec = load(fname);
            String jwks = jwksOf(vec);
            for (Object caseObj : (List<Object>) vec.get("Cases")) {
                Map<String, Object> c = (Map<String, Object>) caseObj;
                String jws = (String) c.get("Jws");
                Instant now = parseNow(c);
                boolean valid = Boolean.TRUE.equals(c.get("Valid"));
                String expected = (String) c.get("ExpectedStatus");

                t.test("vector " + fname + " / " + c.get("Name"), () -> {
                    if (valid) {
                        LicenseStatus status =
                                LicenseClient.verify(jws, jwks, null, null, now);
                        if (expected != null) {
                            assertEquals(STATUS_BY_NAME.get(expected), status,
                                    "status");
                        }
                    } else {
                        LicenseException e = expectLicenseError(
                                () -> LicenseClient.verify(jws, jwks, null, null, now));
                        assertTrue(e.code() == LicenseException.SIGNATURE_INVALID
                                        || e.code() == LicenseException.MALFORMED_INPUT,
                                "expected SIGNATURE_INVALID or MALFORMED_INPUT, got "
                                        + e.code());
                    }
                });
            }
        }

        // -- product / machine binding ------------------------------------ //
        t.test("product and machine binding", () -> {
            Map<String, Object> vec = load("vectors.json");
            String jwks = jwksOf(vec);
            Map<String, Object> c = ((List<Object>) vec.get("Cases")).stream()
                    .map(o -> (Map<String, Object>) o)
                    .filter(m -> "rs256-trial-valid".equals(m.get("Name")))
                    .findFirst().orElseThrow();
            String jws = (String) c.get("Jws");
            Instant now = parseNow(c);
            String mac = "KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG";

            assertEquals(LicenseStatus.VALID_TRIAL,
                    LicenseClient.verify(jws, jwks,
                            "PRD_01KWWPEPM0N070BDAHJ7G09RGV", mac, now),
                    "matching bindings");

            LicenseException product = expectLicenseError(() -> LicenseClient
                    .verify(jws, jwks, "PRD_SOMETHINGELSE", mac, now));
            assertEquals(LicenseException.PRODUCT_MISMATCH, product.code(),
                    "product mismatch code");

            LicenseException machine = expectLicenseError(() -> LicenseClient
                    .verify(jws, jwks, "PRD_01KWWPEPM0N070BDAHJ7G09RGV",
                            "WRONGMACHINE", now));
            assertEquals(LicenseException.COMPUTER_MISMATCH, machine.code(),
                    "computer mismatch code");
        });

        // -- machine identity ---------------------------------------------- //
        t.test("machine identity", () -> {
            assertEquals(52, LicenseClient.machineId().length(),
                    "machineId length");
            assertTrue(!LicenseClient.machineName().isEmpty(),
                    "machineName must be non-empty");
        });

        // -- error names ----------------------------------------------------- //
        t.test("error names", () -> {
            LicenseException e =
                    new LicenseException(LicenseException.SIGNATURE_INVALID);
            assertTrue(e.getMessage().contains("signature"),
                    "message should mention 'signature': " + e.getMessage());
        });
    }

    private VectorTests() {
    }
}
