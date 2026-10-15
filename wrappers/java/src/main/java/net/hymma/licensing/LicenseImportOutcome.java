package net.hymma.licensing;

/**
 * Outcome of {@link LicenseClient#importLicense(String)} — the native
 * {@code hlm_import_result} / the .NET SDK's LicenseImportOutcome.
 */
public enum LicenseImportOutcome {
    /** Verified and installed where the client reads it. */
    INSTALLED(0),
    /** Not a license file this library can read. */
    NOT_A_LICENSE_FILE(1),
    /** No public key was configured, so the file could not be verified. */
    NO_PUBLIC_KEY(2),
    /** The signature does not verify (altered, or another vendor's file). */
    SIGNATURE_INVALID(3),
    /** The file is for a different product. */
    WRONG_PRODUCT(4),
    /** The file is for a different computer. */
    WRONG_COMPUTER(5),
    /** The file could not be written to the license path. */
    WRITE_FAILED(6);

    private final int code;

    LicenseImportOutcome(int code) {
        this.code = code;
    }

    /** The native enum value. */
    public int code() {
        return code;
    }

    /** Maps a native enum value to the constant, or null when it is not one. */
    static LicenseImportOutcome fromCode(int code) {
        for (LicenseImportOutcome o : values()) {
            if (o.code == code) {
                return o;
            }
        }
        return null;
    }
}
