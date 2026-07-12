package com.hymma.licensing;

import java.lang.foreign.MemorySegment;
import java.time.Instant;
import java.util.Optional;

/**
 * High-level licensing client (check / activate / deactivate / refresh).
 *
 * <p>Thin facade over the native hymmalm core. All license logic — JWS
 * verification, status rules, machine fingerprinting, the REST client flow,
 * retry policy and clock-tamper resistance — lives in the native library so
 * every language wrapper behaves identically; this class only marshals.
 *
 * <p>One instance per thread, or serialize calls yourself — same rule as the
 * native handle it wraps.
 *
 * <pre>{@code
 * try (var client = new LicenseClient(LicenseClientOptions.builder()
 *         .productId("PRD_01KWWPEPM0N070BDAHJ7G09RGV")
 *         .clientApiKey("PUB_...")                     // never a MST_ key
 *         .jwksJson(Files.readString(Path.of("signingkeys.json")))
 *         .licensePath(home.resolve(".myapp/license.lic").toString())
 *         .build())) {
 *     LicenseStatus status = client.check();           // trial bootstrap on first run
 *     if (status == LicenseStatus.INVALID_TRIAL) {
 *         client.activate(userEnteredReceiptCode);
 *     }
 * }
 * }</pre>
 */
public final class LicenseClient implements AutoCloseable {

    private MemorySegment handle;

    public LicenseClient(LicenseClientOptions options) {
        if (options == null) {
            throw new NullPointerException("options");
        }
        handle = Native.create(options.baseUrl(), options.productId(),
                options.clientApiKey(), options.jwksJson(),
                options.format().code(), options.validDays(),
                options.machineId(), options.machineName(),
                options.licensePath());
        if (handle.address() == 0) {
            throw new IllegalArgumentException(
                    "hlm_ffi_create rejected the options (missing product/key/"
                    + "JWKS, or no hardware fingerprint available on this platform)");
        }
    }

    // -- operations ------------------------------------------------------ //

    /** Silent check; on a fresh machine this also bootstraps the trial. */
    public LicenseStatus check() {
        return guard(Native.check(handle()));
    }

    /** Attach a purchased receipt code to this machine's license. */
    public LicenseStatus activate(String receiptCode) {
        return guard(Native.activate(handle(), receiptCode));
    }

    /** Free this machine's seat (uninstall flow). */
    public LicenseStatus deactivate() {
        return guard(Native.deactivate(handle()));
    }

    /** Fetch a fresh signed license, ignoring the cache. */
    public LicenseStatus refresh() {
        return guard(Native.refresh(handle()));
    }

    // -- state ------------------------------------------------------------ //

    public LicenseStatus status() {
        return LicenseStatus.fromCode(Native.status(handle()));
    }

    public String statusName() {
        return Native.statusName(handle());
    }

    public String licenseId() {
        return Native.licenseId(handle());
    }

    public String productName() {
        return Native.productName(handle());
    }

    public String buyerEmail() {
        return Native.buyerEmail(handle());
    }

    public boolean liveMode() {
        return Native.liveMode(handle()) != 0;
    }

    public int lastHttpStatus() {
        return Native.lastHttpStatus(handle());
    }

    /** License expiry (UTC); empty when the license carries none. */
    public Optional<Instant> expires() {
        return fromUnix(Native.expires(handle()));
    }

    /** Trial end (UTC); empty when the license carries none. */
    public Optional<Instant> trialEnd() {
        return fromUnix(Native.trialEnd(handle()));
    }

    /** Receipt expiry (UTC); empty when the license carries none. */
    public Optional<Instant> receiptExpires() {
        return fromUnix(Native.receiptExpires(handle()));
    }

    /** A metadata value from the signed license ("" when absent). */
    public String metadata(String key) {
        return Native.metadata(handle(), key);
    }

    // -- statics ------------------------------------------------------------ //

    /**
     * This machine's hardware fingerprint (52-char Crockford Base32) —
     * identical to the .NET SDK's DeviceId on the same machine.
     */
    public static String machineId() {
        return Native.machineId();
    }

    /** This computer's name, as the SDK would send it. */
    public static String machineName() {
        return Native.machineName();
    }

    /**
     * Offline one-shot: verify a signed license string against
     * {@code jwksJson} and report its status at {@code now} (null uses the
     * system clock). Throws {@link LicenseException} when the string is
     * tampered or malformed, or when it is bound to a different product or
     * machine than expected.
     */
    public static LicenseStatus verify(String jws, String jwksJson,
            String expectedProductId, String expectedMachineId, Instant now) {
        long unix = now == null ? 0 : now.getEpochSecond();
        int[] status = new int[1];
        int r = Native.verify(jws, jwksJson, expectedProductId,
                expectedMachineId, unix, status);
        if (r != 0) {
            throw new LicenseException(r);
        }
        return LicenseStatus.fromCode(status[0]);
    }

    // -- lifecycle ------------------------------------------------------------ //

    @Override
    public void close() {
        if (handle != null && handle.address() != 0) {
            Native.destroy(handle);
        }
        handle = MemorySegment.NULL;
    }

    private MemorySegment handle() {
        if (handle == null || handle.address() == 0) {
            throw new IllegalStateException("LicenseClient is closed");
        }
        return handle;
    }

    private LicenseStatus guard(int err) {
        if (err != 0) {
            throw new LicenseException(err, Native.lastErrorDetail(handle()));
        }
        return status();
    }

    private static Optional<Instant> fromUnix(long seconds) {
        return seconds == Long.MIN_VALUE
                ? Optional.empty()
                : Optional.of(Instant.ofEpochSecond(seconds));
    }
}
