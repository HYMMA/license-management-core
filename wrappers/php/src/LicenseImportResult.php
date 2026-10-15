<?php

declare(strict_types=1);

namespace Hymma\Licensing;

/** What happened to an imported license file, with a message written for the end user. */
final class LicenseImportResult
{
    public function __construct(
        public readonly LicenseImportOutcome $outcome,
        public readonly string $message,
        /** Where the file now lives, when it was installed. */
        public readonly ?string $installedPath = null,
    ) {
    }

    public function succeeded(): bool
    {
        return $this->outcome === LicenseImportOutcome::Installed;
    }
}
