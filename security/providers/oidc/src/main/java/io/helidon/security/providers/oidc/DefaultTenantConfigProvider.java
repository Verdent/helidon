package io.helidon.security.providers.oidc;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import javax.annotation.Priority;

import io.helidon.config.Config;
import io.helidon.security.providers.oidc.common.OidcConfig;
import io.helidon.security.providers.oidc.common.OidcServiceConfig;
import io.helidon.security.providers.oidc.spi.TenantConfigFinder;
import io.helidon.security.providers.oidc.spi.TenantConfigProvider;

/**
 * This is the default tenant provider that is not multi-tenant (always returns empty tenant id)
 */
@Priority(100000)
class DefaultTenantConfigProvider implements TenantConfigProvider {

    @Override
    public TenantConfigFinder createTenantConfigFinder(Config config) {
        boolean multiTenant = config.get("multitenant").asBoolean().orElse(false);
        return multiTenant
                ? new MultiTenantConfig(config)
                : new DefaultTenantConfig(config);
    }

    private static class DefaultTenantConfig implements TenantConfigFinder {
        private final AtomicReference<OidcConfig> oidcConfig = new AtomicReference<>();
        private final AtomicReference<Consumer<String>> changeHandler = new AtomicReference<>();

        DefaultTenantConfig(Config config) {
            this.oidcConfig.set(OidcConfig.create(config));

            config.onChange(it -> {
                oidcConfig.set(OidcConfig.create(it));
                Consumer<String> changeHandler = this.changeHandler.get();
                if (changeHandler != null) {
                    changeHandler.accept(DEFAULT_TENANT_ID);
                }
            });
        }

        @Override
        public Optional<OidcConfig> config(String tenantId) {
            return Optional.of(oidcConfig.get());
        }

        @Override
        public void onChange(Consumer<String> tenantIdChangeConsumer) {
            changeHandler.set(tenantIdChangeConsumer);
        }
    }

    private static class MultiTenantConfig extends DefaultTenantConfig {

        private final OidcServiceConfig serviceConfig;

        MultiTenantConfig(Config config) {
            super(config);

            serviceConfig = OidcServiceConfig.builder()
                    .co
                    .build();
            config.get("tenants")
                    .asList(Config.class)
                    .ifPresent(confList -> confList.forEach(this::tenantFromConfig));
        }

        private void tenantFromConfig(Config config) {
            String id = config.get("id").asString()
                    .orElseThrow(() -> new IllegalStateException("Every tenant need to have \"tenant-id\" specified"));
            tenantMap.put(id, OidcConfig.create(config));
        }

        @Override
        public Optional<OidcConfig> config(String tenantId) {
            return Optional.ofNullable(tenantMap.get(tenantId))
                    .or(() -> super.config(tenantId));
        }

    }
}
