package net.hymma.licensing;

/**
 * Why the license server could not be reached — the native
 * {@code hlm_net_failure} / the .NET SDK's NetworkFailureReason.
 */
public enum NetworkFailure {
    /** No transport failure on the last call. */
    NONE(0),
    /** Failed; the cause could not be determined. */
    UNKNOWN(1),
    /** DNS returned no address for the server — typically a company DNS filter. */
    NAME_RESOLUTION(2),
    /** The TLS handshake failed — often an HTTPS-inspecting proxy or security product. */
    SECURE_CONNECTION(3),
    /** A web proxy refused or failed the connection, or demanded credentials (407). */
    PROXY(4),
    /** The server did not answer in time. */
    TIMEOUT(5),
    /** The address was found but the connection was refused or dropped. */
    CONNECTION(6);

    private final int code;

    NetworkFailure(int code) {
        this.code = code;
    }

    /** The native enum value. */
    public int code() {
        return code;
    }

    /** Maps a native enum value to the constant; unknown values map to UNKNOWN. */
    public static NetworkFailure fromCode(int code) {
        for (NetworkFailure f : values()) {
            if (f.code == code) {
                return f;
            }
        }
        return UNKNOWN;
    }
}
