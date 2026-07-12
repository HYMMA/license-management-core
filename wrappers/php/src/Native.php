<?php

declare(strict_types=1);

namespace Hymma\Licensing;

/**
 * Internal FFI binding to the native hymmalm shared library
 * (include/hymma/hlm_ffi.h). The FFI instance is created once and cached
 * statically. The library is located via the HYMMALM_LIB environment
 * variable (full path), a copy placed next to this file, or the standard
 * dynamic-loader search for libhymmalm.so / libhymmalm.dylib / hymmalm.dll.
 *
 * @internal
 */
final class Native
{
    /** Minimal extern declarations matching hymma/hlm_ffi.h exactly. */
    private const CDEF = <<<'C'
typedef struct hlm_ffi_client hlm_ffi_client;

hlm_ffi_client *hlm_ffi_create(const char *base_url,
                               const char *product_id,
                               const char *client_api_key,
                               const char *jwks_json,
                               int format,
                               unsigned valid_days,
                               const char *machine_id,
                               const char *machine_name,
                               const char *license_path);
void hlm_ffi_destroy(hlm_ffi_client *c);

int hlm_ffi_check(hlm_ffi_client *c);
int hlm_ffi_activate(hlm_ffi_client *c, const char *receipt_code);
int hlm_ffi_deactivate(hlm_ffi_client *c);
int hlm_ffi_refresh(hlm_ffi_client *c);

int hlm_ffi_status(hlm_ffi_client *c);
const char *hlm_ffi_status_name(hlm_ffi_client *c);
const char *hlm_ffi_license_id(hlm_ffi_client *c);
const char *hlm_ffi_product_name(hlm_ffi_client *c);
const char *hlm_ffi_buyer_email(hlm_ffi_client *c);
int64_t hlm_ffi_expires(hlm_ffi_client *c);
int64_t hlm_ffi_trial_end(hlm_ffi_client *c);
int64_t hlm_ffi_receipt_expires(hlm_ffi_client *c);
int hlm_ffi_live_mode(hlm_ffi_client *c);
const char *hlm_ffi_metadata(hlm_ffi_client *c, const char *key);
int hlm_ffi_last_http_status(hlm_ffi_client *c);
const char *hlm_ffi_last_error_detail(hlm_ffi_client *c);

const char *hlm_ffi_err_name(int err);
int hlm_ffi_machine_id(char *out, int cap);
int hlm_ffi_machine_name(char *out, int cap);
int hlm_ffi_verify(const char *jws,
                   const char *jwks_json,
                   const char *expected_product_id,
                   const char *expected_machine_id,
                   int64_t now,
                   int *status_out);
C;

    private static ?\FFI $ffi = null;

    private function __construct()
    {
    }

    public static function get(): \FFI
    {
        if (self::$ffi !== null) {
            return self::$ffi;
        }
        $last = null;
        foreach (self::candidates() as $candidate) {
            try {
                self::$ffi = \FFI::cdef(self::CDEF, $candidate);

                return self::$ffi;
            } catch (\Throwable $e) {
                $last = $e; // try the next candidate
            }
        }
        throw new \RuntimeException(
            'cannot load the native hymmalm library; build it with cmake and '
            . 'set HYMMALM_LIB to the full path of libhymmalm.so/.dylib/hymmalm.dll',
            0,
            $last
        );
    }

    /** @return list<string> */
    private static function candidates(): array
    {
        $candidates = [];
        $env = getenv('HYMMALM_LIB');
        if ($env !== false && $env !== '') {
            $candidates[] = $env;
        }
        $names = match (PHP_OS_FAMILY) {
            'Windows' => ['hymmalm.dll'],
            'Darwin' => ['libhymmalm.dylib'],
            default => ['libhymmalm.so'],
        };
        foreach ($names as $name) {
            $candidates[] = __DIR__ . DIRECTORY_SEPARATOR . $name; // bundled alongside the package
            $candidates[] = $name; // standard loader search
        }

        return $candidates;
    }

    /**
     * Convert a `const char *` return value (possibly NULL) to a PHP string.
     * Depending on the PHP version, FFI returns these either as a native
     * string or as a CData pointer.
     */
    public static function str(mixed $ptr): string
    {
        if ($ptr === null) {
            return '';
        }
        if (is_string($ptr)) {
            return $ptr;
        }
        if ($ptr instanceof \FFI\CData) {
            return \FFI::isNull($ptr) ? '' : \FFI::string($ptr);
        }

        return (string) $ptr;
    }

    /** Human-readable name for a native error code (hlm_ffi_err_name). */
    public static function errName(int $code): string
    {
        return self::str(self::get()->hlm_ffi_err_name($code));
    }
}
