package io.helidon.security.providers.oidc.common;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import io.helidon.config.Config;

public final class OidcServiceConfig {

    /**
     * Default tenant id used when requesting configuration for unknown tenant.
     */
    public static final String DEFAULT_TENANT_ID = "@default";

    private final Map<String, OidcConfig> tenantsConfig;

    private OidcServiceConfig(Builder builder) {
        tenantsConfig = builder.tenantsConfig;
    }

    public static OidcServiceConfig create(Config config) {
        return builder().config(config).build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public Optional<OidcConfig> tenantConfig(String tenantId) {
        return Optional.ofNullable(tenantsConfig.get(tenantId))
                .or(() -> Optional.ofNullable(tenantsConfig.get(DEFAULT_TENANT_ID)));
    }

    public static final class Builder implements io.helidon.common.Builder<OidcServiceConfig> {

        private static final String TENANT_ID_CONFIG_NAME = "name";

        private final Map<String, OidcConfig> tenantsConfig = new HashMap<>();

        private Builder() {
        }

        @Override
        public OidcServiceConfig build() {
            return new OidcServiceConfig(this);
        }

        public Builder config(Config config) {
            tenantsConfig.put(DEFAULT_TENANT_ID, OidcConfig.create(config));
            config.get("tenants")
                    .asList(Config.class)
                    .ifPresent(confList -> confList.forEach(this::tenantFromConfig));
            return this;
        }

        private void tenantFromConfig(Config config) {
            String name = config.get(TENANT_ID_CONFIG_NAME).asString()
                    .orElseThrow(() -> new IllegalStateException("Every tenant need to have \"" + TENANT_ID_CONFIG_NAME + "\" "
                                                                         + "specified"));
            tenantsConfig.put(name, OidcConfig.create(config));
        }

    }

}
