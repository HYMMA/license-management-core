package com.hymma.licensing;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

import static com.hymma.licensing.TestRunner.assertEquals;
import static com.hymma.licensing.TestRunner.assertTrue;
import static com.hymma.licensing.TestRunner.expectLicenseError;

/**
 * End-to-end client flow against a local mock of the license API.
 *
 * <p>The mock serves the checked-in signed vectors and a fixed
 * {@code GET /api/DateTime} (2026-07-10T00:00:00Z). HLM_TIMESYNC=off (set by
 * run-tests.sh — Java cannot setenv for its own process) makes the native
 * client resolve its trusted evaluation time from that endpoint, so the
 * expected statuses are deterministic regardless of the real clock.
 */
final class FlowTests {

    static final String PRODUCT = "PRD_01KWWPEPM0N070BDAHJ7G09RGV";
    static final String MACHINE =
            "KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG";
    static final String DEAD_URL = "http://127.0.0.1:1/api/";

    // ------------------------------------------------------------------ //
    // mock license API                                                     //
    // ------------------------------------------------------------------ //

    static final class MockApi implements HttpHandler {
        private static final Pattern CODE_NULL =
                Pattern.compile("\"Code\"\\s*:\\s*null");
        private static final Pattern CODE_SET =
                Pattern.compile("\"Code\"\\s*:\\s*\"");

        final Map<String, String> jwsByCase;
        volatile String licenseCase = "rs256-trial-valid";
        volatile int failStatus; // 0 = healthy
        volatile String failBody = "{}";

        MockApi(Map<String, String> jwsByCase) {
            this.jwsByCase = jwsByCase;
        }

        void reset() {
            licenseCase = "rs256-trial-valid";
            failStatus = 0;
            failBody = "{}";
        }

        @Override
        public void handle(HttpExchange ex) throws IOException {
            String body = new String(ex.getRequestBody().readAllBytes(),
                    StandardCharsets.UTF_8);
            String method = ex.getRequestMethod();
            String path = ex.getRequestURI().getPath();

            if (failStatus != 0) {
                send(ex, failStatus, failBody);
            } else if ("GET".equals(method) && path.startsWith("/api/DateTime")) {
                send(ex, 200, "\"2026-07-10T00:00:00Z\"");
            } else if ("GET".equals(method) && path.startsWith("/api/computer")) {
                send(ex, 200, "{\"id\":\"PC_01KWVTRYM7AXBT1V56M2N3E3AB\"}");
            } else if ("GET".equals(method) && path.startsWith("/api/license")) {
                send(ex, 200, jwsByCase.get(licenseCase));
            } else if ("POST".equals(method)) {
                send(ex, 201, "{}");
            } else if ("PATCH".equals(method) && path.startsWith("/api/license")) {
                if (CODE_NULL.matcher(body).find()) {
                    licenseCase = "rs256-receipt-unregistered";
                } else if (CODE_SET.matcher(body).find()) {
                    licenseCase = "rs256-paid-valid";
                }
                send(ex, 204, "");
            } else {
                send(ex, 404, "{}");
            }
        }

        private static void send(HttpExchange ex, int code, String body)
                throws IOException {
            byte[] data = body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(code, data.length == 0 ? -1 : data.length);
            if (data.length > 0) {
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(data);
                }
            }
            ex.close();
        }
    }

    // ------------------------------------------------------------------ //
    // tests                                                                //
    // ------------------------------------------------------------------ //

    static LicenseClient client(String jwks, String base, String licPath) {
        return new LicenseClient(LicenseClientOptions.builder()
                .baseUrl(base)
                .productId(PRODUCT)
                .clientApiKey("PUB_test")
                .jwksJson(jwks)
                .format(SignedFormat.RS256)
                .machineId(MACHINE)
                .machineName("SHOP-FLOOR-01")
                .licensePath(licPath)
                .build());
    }

    @SuppressWarnings("unchecked")
    static void run(TestRunner t) throws Exception {
        Map<String, Object> vec = VectorTests.load("vectors.json");
        Map<String, String> jwsByCase = new HashMap<>();
        for (Object caseObj : (List<Object>) vec.get("Cases")) {
            Map<String, Object> c = (Map<String, Object>) caseObj;
            jwsByCase.put((String) c.get("Name"), (String) c.get("Jws"));
        }
        String jwks = "[" + Json.write(vec.get("RsaJwk")) + "]";

        MockApi api = new MockApi(jwsByCase);
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.createContext("/api/", api);
        srv.setExecutor(Executors.newCachedThreadPool());
        srv.start();
        String base = "http://127.0.0.1:" + srv.getAddress().getPort() + "/api/";

        try {
            t.test("flow: trial -> activate -> offline cache -> deactivate", () -> {
                api.reset();
                Path lic = Path.of(System.getProperty("java.io.tmpdir"),
                        "hlm-java-flow-test-" + ProcessHandle.current().pid() + ".lic");
                Files.deleteIfExists(lic);
                try {
                    try (LicenseClient c = client(jwks, base, lic.toString())) {
                        assertEquals(LicenseStatus.VALID_TRIAL, c.check(), "check");
                        assertEquals("LIC_01KWVTRYMCAGWHTCVBYFGNJDA0",
                                c.licenseId(), "licenseId");
                        assertEquals("CADshift Nesting", c.productName(),
                                "productName");
                        assertTrue(c.trialEnd().isPresent(),
                                "trialEnd should be present");

                        assertEquals(LicenseStatus.VALID,
                                c.activate("RCPT-CODE-1234"), "activate");
                        assertEquals("jane@example.com", c.buyerEmail(),
                                "buyerEmail");
                        assertEquals("floor-1", c.metadata("seat"),
                                "metadata(seat)");
                        assertTrue(c.liveMode(), "liveMode should be true");
                        assertTrue(c.expires().isPresent(),
                                "expires should be present");
                    }

                    // a fresh client on a dead URL must surface the cached license
                    try (LicenseClient c = client(jwks, DEAD_URL, lic.toString())) {
                        assertEquals(LicenseStatus.VALID, c.check(),
                                "offline check from cache");
                    }

                    try (LicenseClient c = client(jwks, base, lic.toString())) {
                        assertEquals(LicenseStatus.VALID, c.check(),
                                "check before deactivate");
                        assertEquals(LicenseStatus.RECEIPT_UNREGISTERED,
                                c.deactivate(), "deactivate");
                    }
                } finally {
                    Files.deleteIfExists(lic);
                }
            });

            t.test("401 -> INVALID_API_KEY", () -> {
                api.reset();
                api.failStatus = 401;
                try (LicenseClient c = client(jwks, base, null)) {
                    LicenseException e = expectLicenseError(c::check);
                    assertEquals(LicenseException.INVALID_API_KEY, e.code(),
                            "error code");
                }
            });

            t.test("402 -> TRIAL_QUOTA_EXCEEDED with server detail", () -> {
                api.reset();
                api.failStatus = 402;
                api.failBody = "{\"error\":\"trial_quota\",\"detail\":"
                        + "\"Active-trial quota exhausted for this vendor.\"}";
                try (LicenseClient c = client(jwks, base, null)) {
                    LicenseException e = expectLicenseError(c::check);
                    assertEquals(LicenseException.TRIAL_QUOTA_EXCEEDED, e.code(),
                            "error code");
                    assertTrue(e.detail().contains("quota"),
                            "detail should mention quota: " + e.detail());
                }
            });

            t.test("offline without cache -> NETWORK_FAILURE", () -> {
                api.reset();
                try (LicenseClient c = client(jwks, DEAD_URL, null)) {
                    LicenseException e = expectLicenseError(c::check);
                    assertEquals(LicenseException.NETWORK_FAILURE, e.code(),
                            "error code");
                }
            });
        } finally {
            srv.stop(0);
        }
    }

    private FlowTests() {
    }
}
