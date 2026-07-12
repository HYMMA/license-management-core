<?php

declare(strict_types=1);

namespace Hymma\Licensing;

// Allow plain `require 'src/LicenseClient.php';` without composer.
require_once __DIR__ . '/LicenseStatus.php';
require_once __DIR__ . '/SignedFormat.php';
require_once __DIR__ . '/Native.php';
require_once __DIR__ . '/LicenseException.php';

/**
 * High-level licensing client (check / activate / deactivate / refresh).
 *
 * Thin FFI binding over the native hymmalm shared library
 * (include/hymma/hlm_ffi.h). All licensing logic — JWS verification, status
 * rules, machine fingerprinting, the REST client flow, retry policy and
 * clock-tamper resistance — lives in the native core, so every language
 * wrapper behaves identically. This class only marshals.
 *
 * One instance per thread, or serialize calls yourself — same rule as the
 * native handle it wraps.
 *
 * Typical use:
 *
 *     $client = new LicenseClient(
 *         productId: 'PRD_01KWWPEPM0N070BDAHJ7G09RGV',
 *         clientApiKey: 'PUB_...',                       // never a MST_ key
 *         jwksJson: file_get_contents('signingkeys.json'),
 *         licensePath: '/home/me/.myapp/license.lic',
 *     );
 *     $status = $client->check();                        // trial bootstrap on first run
 *     if ($status === LicenseStatus::InvalidTrial) {
 *         $client->activate($userEnteredReceiptCode);
 *     }
 */
class LicenseClient
{
    private ?\FFI\CData $handle;

    /**
     * @param array|string|null $baseUrl Either the base URL string (or null
     *        for the production server), or an options array with the same
     *        keys as the named parameters below.
     */
    public function __construct(
        array|string|null $baseUrl = null,
        ?string $productId = null,
        ?string $clientApiKey = null,
        ?string $jwksJson = null,
        SignedFormat $format = SignedFormat::Rs256,
        int $validDays = 0,
        ?string $machineId = null,
        ?string $machineName = null,
        ?string $licensePath = null,
    ) {
        if (is_array($baseUrl)) {
            $o = $baseUrl;
            $baseUrl = $o['baseUrl'] ?? null;
            $productId = $o['productId'] ?? $productId;
            $clientApiKey = $o['clientApiKey'] ?? $clientApiKey;
            $jwksJson = $o['jwksJson'] ?? $jwksJson;
            $format = $o['format'] ?? $format;
            $validDays = $o['validDays'] ?? $validDays;
            $machineId = $o['machineId'] ?? $machineId;
            $machineName = $o['machineName'] ?? $machineName;
            $licensePath = $o['licensePath'] ?? $licensePath;
        }
        if ($format instanceof SignedFormat) {
            $format = $format->value;
        }

        $handle = Native::get()->hlm_ffi_create(
            $baseUrl,
            $productId,
            $clientApiKey,
            $jwksJson,
            (int) $format,
            $validDays,
            $machineId,
            $machineName,
            $licensePath
        );
        if ($handle === null || \FFI::isNull($handle)) {
            throw new \InvalidArgumentException(
                'hlm_ffi_create rejected the options (missing product/key/'
                . 'JWKS, or no machine fingerprint available on this platform)'
            );
        }
        $this->handle = $handle;
    }

    // -- lifecycle ------------------------------------------------------ //

    public function close(): void
    {
        if ($this->handle !== null) {
            Native::get()->hlm_ffi_destroy($this->handle);
            $this->handle = null;
        }
    }

    public function __destruct()
    {
        $this->close();
    }

    private function h(): \FFI\CData
    {
        if ($this->handle === null) {
            throw new \LogicException('LicenseClient is closed');
        }

        return $this->handle;
    }

    /** @throws LicenseException when the native call returned a nonzero code */
    private function guard(int $err): LicenseStatus
    {
        if ($err !== 0) {
            $detail = Native::str(
                Native::get()->hlm_ffi_last_error_detail($this->h())
            );
            throw new LicenseException($err, $detail);
        }

        return $this->status();
    }

    // -- operations ------------------------------------------------------ //

    /** Silent check; on a fresh machine this also bootstraps the trial. */
    public function check(): LicenseStatus
    {
        return $this->guard(Native::get()->hlm_ffi_check($this->h()));
    }

    /** Attach a purchased receipt code to this machine's license. */
    public function activate(string $receiptCode): LicenseStatus
    {
        return $this->guard(Native::get()->hlm_ffi_activate($this->h(), $receiptCode));
    }

    /** Free this machine's seat (uninstall flow). */
    public function deactivate(): LicenseStatus
    {
        return $this->guard(Native::get()->hlm_ffi_deactivate($this->h()));
    }

    /** Fetch a fresh signed license, ignoring the cache. */
    public function refresh(): LicenseStatus
    {
        return $this->guard(Native::get()->hlm_ffi_refresh($this->h()));
    }

    // -- state ------------------------------------------------------------ //

    public function status(): LicenseStatus
    {
        return LicenseStatus::from(Native::get()->hlm_ffi_status($this->h()));
    }

    public function statusName(): string
    {
        return Native::str(Native::get()->hlm_ffi_status_name($this->h()));
    }

    public function licenseId(): string
    {
        return Native::str(Native::get()->hlm_ffi_license_id($this->h()));
    }

    public function productName(): string
    {
        return Native::str(Native::get()->hlm_ffi_product_name($this->h()));
    }

    public function buyerEmail(): string
    {
        return Native::str(Native::get()->hlm_ffi_buyer_email($this->h()));
    }

    public function liveMode(): bool
    {
        return Native::get()->hlm_ffi_live_mode($this->h()) !== 0;
    }

    public function expires(): ?\DateTimeImmutable
    {
        return self::fromUnix(Native::get()->hlm_ffi_expires($this->h()));
    }

    public function trialEnd(): ?\DateTimeImmutable
    {
        return self::fromUnix(Native::get()->hlm_ffi_trial_end($this->h()));
    }

    public function receiptExpires(): ?\DateTimeImmutable
    {
        return self::fromUnix(Native::get()->hlm_ffi_receipt_expires($this->h()));
    }

    public function metadata(string $key): string
    {
        return Native::str(Native::get()->hlm_ffi_metadata($this->h(), $key));
    }

    public function lastHttpStatus(): int
    {
        return Native::get()->hlm_ffi_last_http_status($this->h());
    }

    // -- stateless helpers ------------------------------------------------ //

    /**
     * This machine's hardware fingerprint (52-char Crockford Base32) —
     * identical to the .NET SDK's DeviceId on the same machine.
     */
    public static function machineId(): string
    {
        $ffi = Native::get();
        $buf = $ffi->new('char[64]');
        $r = $ffi->hlm_ffi_machine_id($buf, 64);
        if ($r !== 0) {
            throw new LicenseException($r);
        }

        return \FFI::string($buf);
    }

    /** This computer's name, as the SDK would send it. */
    public static function machineName(): string
    {
        $ffi = Native::get();
        $buf = $ffi->new('char[256]');
        $r = $ffi->hlm_ffi_machine_name($buf, 256);
        if ($r !== 0) {
            throw new LicenseException($r);
        }

        return \FFI::string($buf);
    }

    /**
     * Offline one-shot: verify a signed license string and report its status
     * at $now (default: the system clock). Throws LicenseException when the
     * string is tampered or malformed.
     */
    public static function verify(
        string $jws,
        string $jwksJson,
        ?string $productId = null,
        ?string $machineId = null,
        ?\DateTimeInterface $now = null,
    ): LicenseStatus {
        $ffi = Native::get();
        $statusOut = $ffi->new('int');
        $r = $ffi->hlm_ffi_verify(
            $jws,
            $jwksJson,
            $productId,
            $machineId,
            $now?->getTimestamp() ?? 0,
            \FFI::addr($statusOut)
        );
        if ($r !== 0) {
            throw new LicenseException($r);
        }

        return LicenseStatus::from($statusOut->cdata);
    }

    /** Unix seconds -> DateTimeImmutable (UTC); INT64_MIN means "none". */
    private static function fromUnix(int $seconds): ?\DateTimeImmutable
    {
        if ($seconds === PHP_INT_MIN) { // HLM_TIME_NONE
            return null;
        }

        return new \DateTimeImmutable('@' . $seconds);
    }
}
