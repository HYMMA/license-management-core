<?php

declare(strict_types=1);

namespace Hymma\Licensing;

/**
 * Outcome of LicenseClient::importLicense() — the native hlm_import_result /
 * the .NET SDK's LicenseImportOutcome.
 */
enum LicenseImportOutcome: int
{
    /** Verified and installed where the client reads it. */
    case Installed = 0;
    /** Not a license file this library can read. */
    case NotALicenseFile = 1;
    /** No public key was configured, so the file could not be verified. */
    case NoPublicKey = 2;
    /** The signature does not verify (altered, or another vendor's file). */
    case SignatureInvalid = 3;
    /** The file is for a different product. */
    case WrongProduct = 4;
    /** The file is for a different computer. */
    case WrongComputer = 5;
    /** The file could not be written to the license path. */
    case WriteFailed = 6;
}
