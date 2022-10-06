package io.helidon.security.providers.oidc;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import javax.annotation.Priority;

import io.helidon.config.Config;
import io.helidon.security.providers.oidc.common.OidcConfig;
import io.helidon.security.providers.oidc.common.TenantConfig;
import io.helidon.security.providers.oidc.spi.TenantConfigFinder;
import io.helidon.security.providers.oidc.spi.TenantConfigProvider;

/**
 * This is the default tenant provider that is not multi-tenant (always returns empty tenant id)
 */
@Priority(100000)
class DefaultTenantConfigProvider implements TenantConfigProvider {

    @Override
    public TenantConfigFinder createTenantConfigFinder(Config config) {
        return new DefaultTenantConfig(config);
    }

    static class DefaultTenantConfig implements TenantConfigFinder {
        private final AtomicReference<OidcConfig> oidcConfig = new AtomicReference<>();
        private final AtomicReference<Consumer<String>> changeHandler = new AtomicReference<>();

        DefaultTenantConfig(Config config) {
            this.oidcConfig.set(OidcConfig.create(config));

            config.onChange(it -> {
                oidcConfig.set(OidcConfig.create(it));
                Consumer<String> changeHandler = this.changeHandler.get();
                if (changeHandler != null) {
                    changeHandler.accept(OidcConfig.DEFAULT_TENANT_ID);
                }
            });
        }

        DefaultTenantConfig(OidcConfig oidcConfig) {
            this.oidcConfig.set(oidcConfig);
        }

        @Override
        public Optional<TenantConfig> config(String tenantId) {
            return Optional.of(oidcConfig.get().tenantConfig(tenantId));
        }

        @Override
        public void onChange(Consumer<String> tenantIdChangeConsumer) {
            changeHandler.set(tenantIdChangeConsumer);
        }
    }
}
