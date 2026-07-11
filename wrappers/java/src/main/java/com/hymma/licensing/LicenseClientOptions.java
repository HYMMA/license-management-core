package com.hymma.licensing;

/**
 * Options for {@link LicenseClient}.
 *
 * @param baseUrl      server base URL; null uses https://license-management.com/api/
 * @param productId    the sellable product (PRD_...) — required
 * @param clientApiKey the vendor's CLIENT key (PUB_...) — required; never ship a MST_ key
 * @param jwksJson     vendor public key(s): one JWK object or a JSON array of JWKs
 *                     (GET /api/signingkeys.json) — required; bake this into the app
 * @param format       signed-license wire format; null defaults to RS256
 * @param validDays    requested license-file validity window; 0 = server default (90)
 * @param machineId    override the hardware fingerprint (tests, containers); null derives it
 * @param machineName  this computer's name as sent to the server; null derives it
 * @param licensePath  offline cache path for the signed license; null disables caching
 */
public record LicenseClientOptions(
        String baseUrl,
        String productId,
        String clientApiKey,
        String jwksJson,
        SignedFormat format,
        int validDays,
        String machineId,
        String machineName,
        String licensePath) {

    public LicenseClientOptions {
        if (format == null) {
            format = SignedFormat.RS256;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String baseUrl;
        private String productId;
        private String clientApiKey;
        private String jwksJson;
        private SignedFormat format = SignedFormat.RS256;
        private int validDays;
        private String machineId;
        private String machineName;
        private String licensePath;

        public Builder baseUrl(String v) {
            this.baseUrl = v;
            return this;
        }

        public Builder productId(String v) {
            this.productId = v;
            return this;
        }

        public Builder clientApiKey(String v) {
            this.clientApiKey = v;
            return this;
        }

        public Builder jwksJson(String v) {
            this.jwksJson = v;
            return this;
        }

        public Builder format(SignedFormat v) {
            this.format = v;
            return this;
        }

        public Builder validDays(int v) {
            this.validDays = v;
            return this;
        }

        public Builder machineId(String v) {
            this.machineId = v;
            return this;
        }

        public Builder machineName(String v) {
            this.machineName = v;
            return this;
        }

        public Builder licensePath(String v) {
            this.licensePath = v;
            return this;
        }

        public LicenseClientOptions build() {
            return new LicenseClientOptions(baseUrl, productId, clientApiKey,
                    jwksJson, format, validDays, machineId, machineName,
                    licensePath);
        }
    }
}
