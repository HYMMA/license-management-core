<?php

declare(strict_types=1);

namespace Hymma\Licensing;

/**
 * Raised when the native core reports an error.
 *
 * getCode() carries the native error code (one of the class constants);
 * $detail / getDetail() carries the server's human-readable refusal reason
 * when it sent one. The message combines hlm_ffi_err_name and the detail.
 */
class LicenseException extends \RuntimeException
{
    public const INVALID_ARGUMENT = -1;
    public const BUFFER_TOO_SMALL = -2;
    public const MALFORMED_INPUT = -3;
    public const SIGNATURE_INVALID = -4;
    public const UNSUPPORTED_ALGORITHM = -5;
    public const NO_LICENSE = -6;
    public const NETWORK_FAILURE = -7;
    public const API_REJECTED = -8;
    public const STORAGE_FAILURE = -9;
    public const PRODUCT_MISMATCH = -10;
    public const COMPUTER_MISMATCH = -11;
    public const INVALID_API_KEY = -12;
    public const TRIAL_QUOTA_EXCEEDED = -13;
    public const PAID_FORMAT_REQUIRED = -14;
    public const PLAN_LIMIT_REACHED = -15;

    public readonly string $detail;

    public function __construct(int $code, string $detail = '')
    {
        $this->detail = $detail;
        $name = Native::errName($code);
        parent::__construct($detail !== '' ? "{$name}: {$detail}" : $name, $code);
    }

    public function getDetail(): string
    {
        return $this->detail;
    }
}
