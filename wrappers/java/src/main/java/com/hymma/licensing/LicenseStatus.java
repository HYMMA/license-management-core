package com.hymma.licensing;

/** Mirrors the native {@code hlm_status} / the .NET SDK's LicenseStatusTitles. */
public enum LicenseStatus {
    UNKNOWN(0),
    EXPIRED(1),
    VALID(2),
    VALID_TRIAL(3),
    INVALID_TRIAL(4),
    RECEIPT_EXPIRED(5),
    RECEIPT_UNREGISTERED(6);

    private final int code;

    LicenseStatus(int code) {
        this.code = code;
    }

    /** The native enum value. */
    public int code() {
        return code;
    }

    /** Maps a native enum value to the constant; unknown values map to UNKNOWN. */
    public static LicenseStatus fromCode(int code) {
        for (LicenseStatus s : values()) {
            if (s.code == code) {
                return s;
            }
        }
        return UNKNOWN;
    }
}
