package com.hymma.licensing;

/** Signed-license wire formats the server can emit. */
public enum SignedFormat {
    RS256(1),
    ES256(2),
    EDDSA(3);

    private final int code;

    SignedFormat(int code) {
        this.code = code;
    }

    /** The native enum value. */
    public int code() {
        return code;
    }

    /** Maps a native enum value to the constant. */
    public static SignedFormat fromCode(int code) {
        for (SignedFormat f : values()) {
            if (f.code == code) {
                return f;
            }
        }
        throw new IllegalArgumentException("unknown SignedFormat code " + code);
    }
}
