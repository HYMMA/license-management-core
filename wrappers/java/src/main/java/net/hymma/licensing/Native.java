package net.hymma.licensing;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * java.lang.foreign (FFM) binding over the flat C ABI in
 * {@code include/hymma/hlm_ffi.h}. Every {@code hlm_ffi_*} symbol is bound
 * here; all licensing logic lives in the native core — this class only
 * marshals strings and integers across the boundary.
 *
 * <p>The shared library is located in this order: the {@code HYMMALM_LIB}
 * environment variable (full path), a library bundled in the jar under
 * {@code /native/&lt;os&gt;-&lt;arch&gt;/} (release jars carry one per
 * platform, extracted to a temp file on first use), then the standard
 * loader search for {@code System.mapLibraryName("hymmalm")}.
 */
final class Native {

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LOOKUP = loadLibrary();

    private static SymbolLookup loadLibrary() {
        String env = System.getenv("HYMMALM_LIB");
        if (env != null && !env.isEmpty()) {
            return lookupOrThrow(env);
        }
        String bundled = extractBundled();
        if (bundled != null) {
            return lookupOrThrow(bundled);
        }
        return lookupOrThrow(System.mapLibraryName("hymmalm"));
    }

    private static SymbolLookup lookupOrThrow(String name) {
        try {
            return SymbolLookup.libraryLookup(name, Arena.global());
        } catch (IllegalArgumentException e) {
            throw new UnsatisfiedLinkError(
                    "cannot load the native hymmalm library (" + name + "); "
                    + "build it with cmake and set HYMMALM_LIB to the full path "
                    + "of libhymmalm.so/.dylib/hymmalm.dll: " + e);
        }
    }

    /** Extract the platform's library bundled in the jar, or null if absent. */
    private static String extractBundled() {
        String os = System.getProperty("os.name", "").toLowerCase();
        String arch = System.getProperty("os.arch", "").toLowerCase();
        String osKey = os.contains("win") ? "windows"
                : os.contains("mac") ? "macos" : "linux";
        String archKey = (arch.equals("aarch64") || arch.equals("arm64"))
                ? "arm64" : "x64";
        String libName = System.mapLibraryName("hymmalm");
        String resource = "/native/" + osKey + "-" + archKey + "/" + libName;

        try (java.io.InputStream in = Native.class.getResourceAsStream(resource)) {
            if (in == null) {
                return null;
            }
            java.nio.file.Path tmp = java.nio.file.Files.createTempFile(
                    "hymmalm-", libName.substring(libName.lastIndexOf('.')));
            java.nio.file.Files.copy(in, tmp,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            tmp.toFile().deleteOnExit();
            return tmp.toAbsolutePath().toString();
        } catch (java.io.IOException e) {
            return null; // fall through to the system loader search
        }
    }

    private static MethodHandle down(String symbol, FunctionDescriptor fd) {
        MemorySegment addr = LOOKUP.find(symbol).orElseThrow(
                () -> new UnsatisfiedLinkError("missing native symbol " + symbol));
        return LINKER.downcallHandle(addr, fd);
    }

    // ------------------------------------------------------------------ //
    // downcall handles — one per hlm_ffi_* symbol                          //
    // ------------------------------------------------------------------ //

    private static final MethodHandle CREATE = down("hlm_ffi_create",
            FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS,
                    JAVA_INT, JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
    private static final MethodHandle DESTROY = down("hlm_ffi_destroy",
            FunctionDescriptor.ofVoid(ADDRESS));
    private static final MethodHandle CHECK = down("hlm_ffi_check",
            FunctionDescriptor.of(JAVA_INT, ADDRESS));
    private static final MethodHandle ACTIVATE = down("hlm_ffi_activate",
            FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
    private static final MethodHandle DEACTIVATE = down("hlm_ffi_deactivate",
            FunctionDescriptor.of(JAVA_INT, ADDRESS));
    private static final MethodHandle REFRESH = down("hlm_ffi_refresh",
            FunctionDescriptor.of(JAVA_INT, ADDRESS));
    private static final MethodHandle STATUS = down("hlm_ffi_status",
            FunctionDescriptor.of(JAVA_INT, ADDRESS));
    private static final MethodHandle STATUS_NAME = down("hlm_ffi_status_name",
            FunctionDescriptor.of(ADDRESS, ADDRESS));
    private static final MethodHandle LICENSE_ID = down("hlm_ffi_license_id",
            FunctionDescriptor.of(ADDRESS, ADDRESS));
    private static final MethodHandle PRODUCT_NAME = down("hlm_ffi_product_name",
            FunctionDescriptor.of(ADDRESS, ADDRESS));
    private static final MethodHandle BUYER_EMAIL = down("hlm_ffi_buyer_email",
            FunctionDescriptor.of(ADDRESS, ADDRESS));
    private static final MethodHandle EXPIRES = down("hlm_ffi_expires",
            FunctionDescriptor.of(JAVA_LONG, ADDRESS));
    private static final MethodHandle TRIAL_END = down("hlm_ffi_trial_end",
            FunctionDescriptor.of(JAVA_LONG, ADDRESS));
    private static final MethodHandle RECEIPT_EXPIRES = down("hlm_ffi_receipt_expires",
            FunctionDescriptor.of(JAVA_LONG, ADDRESS));
    private static final MethodHandle LIVE_MODE = down("hlm_ffi_live_mode",
            FunctionDescriptor.of(JAVA_INT, ADDRESS));
    private static final MethodHandle METADATA = down("hlm_ffi_metadata",
            FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS));
    private static final MethodHandle LAST_HTTP_STATUS = down("hlm_ffi_last_http_status",
            FunctionDescriptor.of(JAVA_INT, ADDRESS));
    private static final MethodHandle LAST_ERROR_DETAIL = down("hlm_ffi_last_error_detail",
            FunctionDescriptor.of(ADDRESS, ADDRESS));
    private static final MethodHandle ERR_NAME = down("hlm_ffi_err_name",
            FunctionDescriptor.of(ADDRESS, JAVA_INT));
    private static final MethodHandle MACHINE_ID = down("hlm_ffi_machine_id",
            FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
    private static final MethodHandle MACHINE_NAME = down("hlm_ffi_machine_name",
            FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
    private static final MethodHandle VERIFY = down("hlm_ffi_verify",
            FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS,
                    JAVA_LONG, ADDRESS));

    private Native() {
    }

    // ------------------------------------------------------------------ //
    // marshalling helpers                                                  //
    // ------------------------------------------------------------------ //

    /** NUL-terminated UTF-8 copy of {@code s} in {@code arena}; null maps to NULL. */
    private static MemorySegment cstr(Arena arena, String s) {
        return s == null ? MemorySegment.NULL : arena.allocateUtf8String(s);
    }

    /** Reads a NUL-terminated UTF-8 native string; NULL maps to "". */
    private static String str(MemorySegment s) {
        if (s == null || s.address() == 0) {
            return "";
        }
        return s.reinterpret(Long.MAX_VALUE).getUtf8String(0);
    }

    private static RuntimeException rethrow(Throwable t) {
        if (t instanceof RuntimeException re) {
            return re;
        }
        if (t instanceof Error e) {
            throw e;
        }
        return new IllegalStateException("native call failed", t);
    }

    // ------------------------------------------------------------------ //
    // typed wrappers                                                       //
    // ------------------------------------------------------------------ //

    static MemorySegment create(String baseUrl, String productId,
            String clientApiKey, String jwksJson, int format, int validDays,
            String machineId, String machineName, String licensePath) {
        try (Arena a = Arena.ofConfined()) {
            return (MemorySegment) CREATE.invokeExact(
                    cstr(a, baseUrl), cstr(a, productId), cstr(a, clientApiKey),
                    cstr(a, jwksJson), format, validDays, cstr(a, machineId),
                    cstr(a, machineName), cstr(a, licensePath));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static void destroy(MemorySegment c) {
        try {
            DESTROY.invokeExact(c);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static int check(MemorySegment c) {
        try {
            return (int) CHECK.invokeExact(c);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static int activate(MemorySegment c, String receiptCode) {
        try (Arena a = Arena.ofConfined()) {
            return (int) ACTIVATE.invokeExact(c, cstr(a, receiptCode));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static int deactivate(MemorySegment c) {
        try {
            return (int) DEACTIVATE.invokeExact(c);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static int refresh(MemorySegment c) {
        try {
            return (int) REFRESH.invokeExact(c);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static int status(MemorySegment c) {
        try {
            return (int) STATUS.invokeExact(c);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static String statusName(MemorySegment c) {
        try {
            return str((MemorySegment) STATUS_NAME.invokeExact(c));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static String licenseId(MemorySegment c) {
        try {
            return str((MemorySegment) LICENSE_ID.invokeExact(c));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static String productName(MemorySegment c) {
        try {
            return str((MemorySegment) PRODUCT_NAME.invokeExact(c));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static String buyerEmail(MemorySegment c) {
        try {
            return str((MemorySegment) BUYER_EMAIL.invokeExact(c));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static long expires(MemorySegment c) {
        try {
            return (long) EXPIRES.invokeExact(c);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static long trialEnd(MemorySegment c) {
        try {
            return (long) TRIAL_END.invokeExact(c);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static long receiptExpires(MemorySegment c) {
        try {
            return (long) RECEIPT_EXPIRES.invokeExact(c);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static int liveMode(MemorySegment c) {
        try {
            return (int) LIVE_MODE.invokeExact(c);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static String metadata(MemorySegment c, String key) {
        try (Arena a = Arena.ofConfined()) {
            return str((MemorySegment) METADATA.invokeExact(c, cstr(a, key)));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static int lastHttpStatus(MemorySegment c) {
        try {
            return (int) LAST_HTTP_STATUS.invokeExact(c);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static String lastErrorDetail(MemorySegment c) {
        try {
            return str((MemorySegment) LAST_ERROR_DETAIL.invokeExact(c));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static String errName(int err) {
        try {
            return str((MemorySegment) ERR_NAME.invokeExact(err));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static String machineId() {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment buf = a.allocate(64);
            int r = (int) MACHINE_ID.invokeExact(buf, 64);
            if (r != 0) {
                throw new LicenseException(r);
            }
            return buf.getUtf8String(0);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static String machineName() {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment buf = a.allocate(256);
            int r = (int) MACHINE_NAME.invokeExact(buf, 256);
            if (r != 0) {
                throw new LicenseException(r);
            }
            return buf.getUtf8String(0);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /** Returns the native error code; on 0 the status enum is in statusOut[0]. */
    static int verify(String jws, String jwksJson, String expectedProductId,
            String expectedMachineId, long now, int[] statusOut) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment out = a.allocate(JAVA_INT);
            int r = (int) VERIFY.invokeExact(cstr(a, jws), cstr(a, jwksJson),
                    cstr(a, expectedProductId), cstr(a, expectedMachineId),
                    now, out);
            statusOut[0] = out.get(JAVA_INT, 0);
            return r;
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }
}
