package net.hymma.licensing;

import java.util.Optional;

/** What happened to an imported license file, with a message written for the end user. */
public final class LicenseImportResult {

    private final LicenseImportOutcome outcome;
    private final String message;
    private final String installedPath;

    LicenseImportResult(LicenseImportOutcome outcome, String message, String installedPath) {
        this.outcome = outcome;
        this.message = message;
        this.installedPath = installedPath;
    }

    public LicenseImportOutcome outcome() {
        return outcome;
    }

    public boolean succeeded() {
        return outcome == LicenseImportOutcome.INSTALLED;
    }

    /** End-user message for the outcome. */
    public String message() {
        return message;
    }

    /** Where the file now lives, when it was installed. */
    public Optional<String> installedPath() {
        return Optional.ofNullable(installedPath);
    }

    @Override
    public String toString() {
        return "LicenseImportResult(" + outcome + ", " + message + ")";
    }
}
