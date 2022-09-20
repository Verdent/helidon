package io.helidon.security.providers.oidc.common;

import java.util.HashMap;
import java.util.Map;

import io.helidon.config.Config;

/**
 * TODO javadoc
 */
public final class OidcServiceConfig extends OidcConfig {

    private final Map<String, OidcConfig> tenantConfigurations;

    OidcServiceConfig(Builder builder) {
        super(builder);
        tenantConfigurations = Map.copyOf(builder.tenantConfigurations);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static OidcServiceConfig create(Config config) {
        return builder().config(config).build();
    }

    public OidcConfig tenantOidcConfig(String tenantId) {
        return tenantConfigurations.getOrDefault(tenantId, this);
    }

    public static final class Builder extends OidcConfig.Builder {

        private final Map<String, OidcConfig> tenantConfigurations = new HashMap<>();

        private Builder() {
        }

        @Override
        public OidcServiceConfig build() {
            super.build();
            return super.build();
        }

        public Builder addTenantConfiguration(String tenant, OidcConfig config) {
            tenantConfigurations.put(tenant, config);
            return this;
        }


    }
}
