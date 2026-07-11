package com.hymma.licensing;

/**
 * Raised when the native core reports an error.
 *
 * <p>{@link #code()} is the classified native error code (negative — see the
 * table below); {@link #detail()} carries the server's human-readable refusal
 * reason when it sent one. The message combines the native error name
 * ({@code hlm_ffi_err_name}) with the detail.
 *
 * <pre>
 *  -1 invalid argument        -6 no license         -11 computer mismatch
 *  -2 buffer too small        -7 network failure    -12 invalid API key
 *  -3 malformed input         -8 API rejected       -13 trial quota exceeded
 *  -4 signature invalid       -9 storage failure    -14 paid format required
 *  -5 unsupported algorithm  -10 product mismatch   -15 plan limit reached
 * </pre>
 */
public class LicenseException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public static final int INVALID_ARGUMENT = -1;
    public static final int BUFFER_TOO_SMALL = -2;
    public static final int MALFORMED_INPUT = -3;
    public static final int SIGNATURE_INVALID = -4;
    public static final int UNSUPPORTED_ALGORITHM = -5;
    public static final int NO_LICENSE = -6;
    public static final int NETWORK_FAILURE = -7;
    public static final int API_REJECTED = -8;
    public static final int STORAGE_FAILURE = -9;
    public static final int PRODUCT_MISMATCH = -10;
    public static final int COMPUTER_MISMATCH = -11;
    public static final int INVALID_API_KEY = -12;
    public static final int TRIAL_QUOTA_EXCEEDED = -13;
    public static final int PAID_FORMAT_REQUIRED = -14;
    public static final int PLAN_LIMIT_REACHED = -15;

    private final int code;
    private final String detail;

    public LicenseException(int code) {
        this(code, "");
    }

    public LicenseException(int code, String detail) {
        super(detail == null || detail.isEmpty()
                ? Native.errName(code)
                : Native.errName(code) + ": " + detail);
        this.code = code;
        this.detail = detail == null ? "" : detail;
    }

    /** The classified native error code (negative). */
    public int code() {
        return code;
    }

    /** The server's human-readable refusal detail ("" when none). */
    public String detail() {
        return detail;
    }
}
