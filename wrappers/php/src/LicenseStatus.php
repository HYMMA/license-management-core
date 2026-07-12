<?php

declare(strict_types=1);

namespace Hymma\Licensing;

/**
 * Mirrors the native hlm_status / the .NET SDK's LicenseStatusTitles.
 */
enum LicenseStatus: int
{
    case Unknown = 0;
    case Expired = 1;
    case Valid = 2;
    case ValidTrial = 3;
    case InvalidTrial = 4;
    case ReceiptExpired = 5;
    case ReceiptUnregistered = 6;
}
