package net.hymma.licensing;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Tiny dependency-free test harness: runs the vector and flow suites, prints
 * pass/fail per test and a summary, and exits nonzero on any failure.
 *
 * <p>Run via {@code ./run-tests.sh}, which sets HLM_TIMESYNC=off (required —
 * it pins the native trusted time to the mock server's /api/DateTime) and
 * HYMMALM_LIB before launching the JVM.
 */
public final class TestRunner {

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws Exception;
    }

    private int passed;
    private final List<String> failures = new ArrayList<>();

    void test(String name, ThrowingRunnable body) {
        try {
            body.run();
            passed++;
            System.out.println("PASS " + name);
        } catch (Throwable t) {
            failures.add(name + ": " + t);
            System.out.println("FAIL " + name);
            t.printStackTrace(System.out);
        }
    }

    // -- assertions ------------------------------------------------------ //

    static void assertTrue(boolean cond, String msg) {
        if (!cond) {
            throw new AssertionError(msg);
        }
    }

    static void assertEquals(Object expected, Object actual, String msg) {
        if (!Objects.equals(expected, actual)) {
            throw new AssertionError(
                    msg + " — expected <" + expected + "> but was <" + actual + ">");
        }
    }

    /** Runs {@code body} and returns the LicenseException it must throw. */
    static LicenseException expectLicenseError(ThrowingRunnable body) {
        try {
            body.run();
        } catch (LicenseException e) {
            return e;
        } catch (Exception e) {
            throw new AssertionError("expected LicenseException, got " + e, e);
        }
        throw new AssertionError("expected LicenseException, nothing was thrown");
    }

    // -- entry point ------------------------------------------------------ //

    public static void main(String[] args) throws Exception {
        if (!"off".equals(System.getenv("HLM_TIMESYNC"))) {
            System.out.println(
                    "WARNING: HLM_TIMESYNC is not 'off' — flow tests are only "
                    + "deterministic when run via ./run-tests.sh");
        }

        TestRunner t = new TestRunner();
        VectorTests.run(t);
        FlowTests.run(t);

        System.out.println();
        System.out.printf("%d passed, %d failed%n", t.passed, t.failures.size());
        for (String f : t.failures) {
            System.out.println("  FAILED: " + f);
        }
        System.exit(t.failures.isEmpty() ? 0 : 1);
    }
}
