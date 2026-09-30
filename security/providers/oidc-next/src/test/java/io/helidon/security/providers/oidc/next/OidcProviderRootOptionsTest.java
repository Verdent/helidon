/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.security.providers.oidc.next;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import io.helidon.config.Config;
import io.helidon.config.ConfigSources;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcProviderRootOptionsTest {
    private static final Duration RETRY_INTERVAL = Duration.ofSeconds(2);
    private static final OidcRemoteWorkConfig REMOTE_WORK = OidcRemoteWorkConfig.builder()
            .maxConcurrent(3).maxQueued(2).admissionTimeout(Duration.ofMillis(25)).buildPrototype();
    private static final List<Map<String, String>> ROOT_OPTIONS = List.of(
            Map.of("initialization-retry-interval", "PT2S"),
            Map.of("initialization-retry-interval", "PT10S"),
            Map.of("initialization-max-queued", "0"),
            Map.of("initialization-max-queued", "128"),
            Map.of("outbound-mutual-tls", "false"),
            Map.of("client-credentials-remote-work.max-concurrent", "3"),
            Map.of("client-credentials-remote-work.max-concurrent", "32"),
            Map.of("client-credentials-remote-work.max-queued", "0"),
            Map.of("client-credentials-remote-work.admission-timeout", "PT0S"),
            Map.of("token-exchange-remote-work.max-concurrent", "3"),
            Map.of("token-exchange-remote-work.max-concurrent", "32"));
    private static final Map<String, String> ALL_TENANT_OPTIONS = Map.ofEntries(
            Map.entry("enabled", "false"),
            Map.entry("initialization-retry-interval", "PT2S"),
            Map.entry("initialization-max-queued", "7"),
            Map.entry("issuer", "https://issuer.example"),
            Map.entry("client-id", "root-client"),
            Map.entry("client-secret", "root-secret"),
            Map.entry("token-endpoint-auth-method", "CLIENT_SECRET_POST"),
            Map.entry("outbound-mutual-tls", "true"),
            Map.entry("id-token.clock-skew", "PT30S"),
            Map.entry("client-assertion.lifetime", "PT20S"),
            Map.entry("webclient.connect-timeout", "PT2S"),
            Map.entry("jwk-set.refresh-interval", "PT11M"),
            Map.entry("client-credentials-remote-work.max-concurrent", "3"),
            Map.entry("token-exchange-remote-work.max-concurrent", "3"),
            Map.entry("endpoints.token-endpoint-uri", "https://issuer.example/token"),
            Map.entry("protected-resource.challenge-realm", "root-realm"),
            Map.entry("authorization-code.enabled", "false"),
            Map.entry("endpoint-policy.authentication-failure-response", "UNAUTHORIZED"),
            Map.entry("logout.enabled", "false"),
            Map.entry("user-info.enabled", "false"),
            Map.entry("token-transport.secure-transport-required", "false"),
            Map.entry("subject-mapping.principal-name-claim-paths.0", "display_name"),
            Map.entry("cookies.local-authentication-cookie-name", "root-auth"));

    @Test
    void rootBuilderPreservesOperationalOptions() {
        OidcProviderConfig provider = OidcProviderConfig.builder()
                .issuer("https://issuer.example")
                .initializationRetryInterval(RETRY_INTERVAL)
                .initializationMaxQueued(7)
                .clientCredentialsRemoteWork(REMOTE_WORK)
                .tokenExchangeRemoteWork(REMOTE_WORK)
                .buildPrototype();
        OidcTenantConfig tenant = provider.tenants().get("default");

        assertThat(tenant.initializationRetryInterval(), is(RETRY_INTERVAL));
        assertThat(tenant.initializationMaxQueued(), is(7));
        assertThat(tenant.clientCredentialsRemoteWork(), is(REMOTE_WORK));
        assertThat(tenant.tokenExchangeRemoteWork(), is(REMOTE_WORK));
        assertTenantOptions(tenant, OidcTenantConfig.builder()
                .issuer("https://issuer.example")
                .initializationRetryInterval(RETRY_INTERVAL)
                .initializationMaxQueued(7)
                .clientCredentialsRemoteWork(REMOTE_WORK)
                .tokenExchangeRemoteWork(REMOTE_WORK)
                .buildPrototype());
    }

    @Test
    void rootConfigPreservesOperationalOptions() {
        Config config = config(Map.of("issuer", "https://issuer.example",
                                      "initialization-retry-interval", "PT2S",
                                      "initialization-max-queued", "7",
                                      "client-credentials-remote-work.max-concurrent", "3",
                                      "client-credentials-remote-work.max-queued", "2",
                                      "client-credentials-remote-work.admission-timeout", "PT0.025S",
                                      "token-exchange-remote-work.max-concurrent", "3",
                                      "token-exchange-remote-work.max-queued", "2",
                                      "token-exchange-remote-work.admission-timeout", "PT0.025S"));
        OidcProviderConfig provider = OidcProviderConfig.create(config);
        OidcTenantConfig tenant = provider.tenants().get("default");

        assertThat(tenant.initializationRetryInterval(), is(RETRY_INTERVAL));
        assertThat(tenant.tokenExchangeRemoteWork(), is(REMOTE_WORK));
        assertTenantOptions(tenant, OidcTenantConfig.create(config));
    }

    @Test
    void rootBuilderRecognizesRetryIntervalAlone() {
        OidcProviderConfig provider = OidcProviderConfig.builder()
                .initializationRetryInterval(RETRY_INTERVAL).buildPrototype();

        assertThat(provider.defaultTenant(), is(Optional.of("default")));
        assertThat(provider.tenants().get("default").initializationRetryInterval(), is(RETRY_INTERVAL));
    }

    @Test
    void rootBuilderRecognizesClientCredentialsLimitsAloneAndDefaultsRemainConsistent() {
        OidcProviderConfig provider = OidcProviderConfig.builder().clientCredentialsRemoteWork(REMOTE_WORK).buildPrototype();
        assertThat(provider.defaultTenant(), is(Optional.of("default")));
        assertThat(provider.tenants().get("default").clientCredentialsRemoteWork(), is(REMOTE_WORK));
        OidcRemoteWorkConfig defaults = OidcTenantConfig.create().clientCredentialsRemoteWork();
        assertThat(defaults.maxConcurrent(), is(32));
        assertThat(defaults.maxQueued(), is(128));
        assertThat(defaults.admissionTimeout(), is(Duration.ofSeconds(1)));
    }

    @Test
    void invalidClientCredentialsLimitsFailForRootAndNamedTenants() {
        for (Map<String, String> invalid : List.of(Map.of("max-concurrent", "0"), Map.of("max-concurrent", "-1"),
                                                  Map.of("max-queued", "-1"), Map.of("admission-timeout", "PT-1S"))) {
            for (String prefix : List.of("", "tenants.named.")) {
                Map<String, String> values = new LinkedHashMap<>();
                invalid.forEach((name, value) -> values.put(prefix + "client-credentials-remote-work." + name, value));
                assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.create(config(values)));
            }
        }
        assertThrows(IllegalArgumentException.class, () -> OidcProviderConfig.builder()
                .clientCredentialsRemoteWork(work -> work.maxConcurrent(0)).buildPrototype());
        assertThrows(IllegalArgumentException.class, () -> OidcTenantConfig.builder()
                .clientCredentialsRemoteWork(work -> work.maxQueued(-1)).buildPrototype());
    }

    @Test
    void runtimeClientCredentialsLimiterUsesRootConfigurationIndependentlyOfTokenExchange() {
        OidcProviderConfig config = OidcProviderConfig.builder()
                .clientCredentialsRemoteWork(work -> work.maxConcurrent(1).maxQueued(0)).buildPrototype();
        OidcTenantRuntimeRegistry registry = OidcTenantRuntimeRegistry.create(config);
        try {
            OidcTenantContext context = registry.tenantContext("default").orElseThrow();
            OidcRemoteWorkLimiter limiter = context.clientCredentialsRemoteWorkLimiter();
            try (var _ = limiter.acquireActive().orElseThrow()) {
                assertThat(limiter.acquireActive().isEmpty(), is(true));
                try (var _ = context.tokenExchangeRemoteWorkLimiter().acquireActive().orElseThrow()) {
                    assertThat(context.tokenExchangeRemoteWorkLimiter().activeCount(), is(1));
                }
            }
            assertThat(limiter.activeCount(), is(0));
        } finally {
            registry.close();
        }
    }

    @Test
    void rootBuilderRecognizesInitializationQueueLimitAlone() {
        OidcProviderConfig provider = OidcProviderConfig.builder().initializationMaxQueued(0).buildPrototype();

        assertThat(provider.defaultTenant(), is(Optional.of("default")));
        assertThat(provider.tenants().get("default").initializationMaxQueued(), is(0));
        assertThat(OidcTenantConfig.create().initializationMaxQueued(), is(128));
    }

    @Test
    void invalidInitializationQueueLimitsAreRejectedForRootNamedAndDisabledTenants() {
        for (boolean enabled : List.of(false, true)) {
            assertThrows(IllegalArgumentException.class,
                         () -> OidcTenantConfig.builder().enabled(enabled).initializationMaxQueued(-1).buildPrototype());
            assertThrows(IllegalArgumentException.class,
                         () -> OidcProviderConfig.builder().enabled(enabled).initializationMaxQueued(-1).buildPrototype());
            for (String prefix : List.of("", "tenants.named.")) {
                IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                        () -> OidcProviderConfig.create(config(Map.of(prefix + "enabled", Boolean.toString(enabled),
                                                                     prefix + "initialization-max-queued", "-1"))));
                assertThat(failure.getMessage(), containsString("initialization-max-queued must not be negative"));
            }
        }
    }

    @Test
    void rootBuilderRecognizesTokenExchangeLimitsAlone() {
        OidcProviderConfig provider = OidcProviderConfig.builder().tokenExchangeRemoteWork(REMOTE_WORK).buildPrototype();

        assertThat(provider.defaultTenant(), is(Optional.of("default")));
        assertThat(provider.tenants().get("default").tokenExchangeRemoteWork(), is(REMOTE_WORK));
    }

    @Test
    void rootConfigRecognizesExplicitOperationalOptionsIncludingDefaults() {
        for (Map<String, String> options : ROOT_OPTIONS) {
            Config config = config(options);
            OidcProviderConfig provider = OidcProviderConfig.create(config);

            assertThat(options.toString(), provider.defaultTenant(), is(Optional.of("default")));
            assertTenantOptions(provider.tenants().get("default"), OidcTenantConfig.create(config));
        }
    }

    @Test
    void rootConfigRejectsOperationalOptionsAlongsideNamedTenants() {
        for (Map<String, String> options : ROOT_OPTIONS) {
            Map<String, String> values = new LinkedHashMap<>(options);
            values.put("tenants.named.enabled", "false");

            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                    () -> OidcProviderConfig.create(config(values)));

            assertThat(failure.getMessage(), containsString("Root tenant configuration cannot be combined with tenants"));
        }
    }

    @Test
    void rootBuilderRejectsChangedOperationalOptionsAlongsideNamedTenants() {
        List<Consumer<OidcProviderConfig.Builder>> options = List.of(
                builder -> builder.initializationRetryInterval(RETRY_INTERVAL),
                builder -> builder.initializationMaxQueued(7),
                builder -> builder.clientCredentialsRemoteWork(REMOTE_WORK),
                builder -> builder.tokenExchangeRemoteWork(REMOTE_WORK));
        for (Consumer<OidcProviderConfig.Builder> option : options) {
            OidcProviderConfig.Builder builder = OidcProviderConfig.builder()
                    .putTenant("named", OidcTenantConfig.create());
            option.accept(builder);

            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, builder::buildPrototype);

            assertThat(failure.getMessage(), containsString("Root tenant configuration cannot be combined with tenants"));
        }
    }

    @Test
    void explicitNamedTenantOptionsArePreserved() {
        OidcProviderConfig provider = OidcProviderConfig.create(config(Map.of(
                "tenants.named.initialization-retry-interval", "PT2S",
                "tenants.named.initialization-max-queued", "7",
                "tenants.named.client-credentials-remote-work.max-concurrent", "3",
                "tenants.named.client-credentials-remote-work.max-queued", "2",
                "tenants.named.client-credentials-remote-work.admission-timeout", "PT0.025S",
                "tenants.named.token-exchange-remote-work.max-concurrent", "3",
                "tenants.named.token-exchange-remote-work.max-queued", "2",
                "tenants.named.token-exchange-remote-work.admission-timeout", "PT0.025S")));

        assertThat(provider.defaultTenant(), is(Optional.of("named")));
        assertThat(provider.tenants().get("named").initializationRetryInterval(), is(RETRY_INTERVAL));
        assertThat(provider.tenants().get("named").initializationMaxQueued(), is(7));
        assertThat(provider.tenants().get("named").clientCredentialsRemoteWork(), is(REMOTE_WORK));
        assertThat(provider.tenants().get("named").tokenExchangeRemoteWork(), is(REMOTE_WORK));
    }

    @Test
    void emptyAndDefaultValuedBuildersDoNotCreateAnImplicitTenant() {
        OidcTenantConfig defaults = OidcTenantConfig.create();

        assertThat(OidcProviderConfig.create().tenants().isEmpty(), is(true));
        assertThat(OidcProviderConfig.builder()
                .initializationRetryInterval(defaults.initializationRetryInterval())
                .initializationMaxQueued(defaults.initializationMaxQueued())
                .clientCredentialsRemoteWork(defaults.clientCredentialsRemoteWork())
                .tokenExchangeRemoteWork(defaults.tokenExchangeRemoteWork())
                .buildPrototype().tenants().isEmpty(), is(true));
    }

    @Test
    void allCurrentTenantOptionGroupsHaveRootAndNamedConfigParity() {
        // Disable the tenant so independent option groups can be tested without enabling unrelated OIDC flows.
        OidcTenantConfig disabled = OidcTenantConfig.builder().enabled(false).buildPrototype();
        for (Map.Entry<String, String> option : ALL_TENANT_OPTIONS.entrySet()) {
            Map<String, String> values = new LinkedHashMap<>();
            values.put("enabled", "false");
            values.put(option.getKey(), option.getValue());
            Config config = config(values);
            OidcTenantConfig expected = OidcTenantConfig.create(config);
            OidcTenantConfig baseline = option.getKey().equals("enabled") ? OidcTenantConfig.create() : disabled;
            if (option.getKey().startsWith("webclient.")) {
                assertThat(expected.webClient().connectTimeout(), not(baseline.webClient().connectTimeout()));
            } else {
                assertThat(option.getKey(), OidcTenantConfig.builder().from(expected)
                        .webClient(baseline.webClient()).buildPrototype(), not(baseline));
            }

            OidcProviderConfig root = OidcProviderConfig.create(config);
            Map<String, String> namedValues = new LinkedHashMap<>();
            values.forEach((key, value) -> namedValues.put("tenants.named." + key, value));
            OidcProviderConfig named = OidcProviderConfig.create(config(namedValues));

            assertTenantOptions(root.tenants().get("default"), expected);
            assertTenantOptions(named.tenants().get("named"), expected);
        }
    }

    @Test
    void allCurrentTenantOptionsHaveProgrammaticRootParity() {
        OidcTenantConfig expected = OidcTenantConfig.create(config(ALL_TENANT_OPTIONS));
        OidcProviderConfig root = OidcProviderConfig.builder()
                .enabled(expected.enabled())
                .initializationRetryInterval(expected.initializationRetryInterval())
                .initializationMaxQueued(expected.initializationMaxQueued())
                .issuer(expected.issuer().orElseThrow())
                .clientId(expected.clientId().orElseThrow())
                .clientSecret(expected.clientSecret().orElseThrow())
                .tokenEndpointAuthenticationMethod(expected.tokenEndpointAuthenticationMethod().orElseThrow())
                .outboundMutualTls(expected.outboundMutualTls())
                .idToken(expected.idToken())
                .clientAssertion(expected.clientAssertion())
                .webClient(expected.webClient())
                .jwkSet(expected.jwkSet())
                .clientCredentialsRemoteWork(expected.clientCredentialsRemoteWork())
                .tokenExchangeRemoteWork(expected.tokenExchangeRemoteWork())
                .endpoints(expected.endpoints())
                .protectedResource(expected.protectedResource().orElseThrow())
                .authorizationCode(expected.authorizationCode().orElseThrow())
                .endpointPolicy(expected.endpointPolicy())
                .logout(expected.logout().orElseThrow())
                .userInfo(expected.userInfo().orElseThrow())
                .tokenTransport(expected.tokenTransport())
                .subjectMapping(expected.subjectMapping())
                .cookies(expected.cookies())
                .buildPrototype();

        assertThat(root.tenants().get("default"), is(expected));
    }

    @Test
    void rootOperationalOptionsSupportTenantNamingBuilderReuseAndCopies() {
        OidcProviderConfig.Builder builder = OidcProviderConfig.builder().defaultTenant("selected")
                .initializationRetryInterval(RETRY_INTERVAL).initializationMaxQueued(7)
                .clientCredentialsRemoteWork(REMOTE_WORK).tokenExchangeRemoteWork(REMOTE_WORK);
        OidcProviderConfig first = builder.buildPrototype();
        OidcProviderConfig second = builder.buildPrototype();
        OidcProviderConfig copy = OidcProviderConfig.builder().from(first).buildPrototype();

        assertThat(first.defaultTenant(), is(Optional.of("selected")));
        assertThat(first.tenants().get("selected").initializationRetryInterval(), is(RETRY_INTERVAL));
        assertThat(first.tenants().get("selected").initializationMaxQueued(), is(7));
        assertThat(first.tenants().get("selected").clientCredentialsRemoteWork(), is(REMOTE_WORK));
        assertThat(first.tenants().get("selected").tokenExchangeRemoteWork(), is(REMOTE_WORK));
        assertThat(second.tenants(), is(first.tenants()));
        assertThat(copy.tenants(), is(first.tenants()));
        OidcProviderConfig fromConfig = OidcProviderConfig.create(config(Map.of(
                "default-tenant", "selected", "initialization-retry-interval", "PT2S")));
        assertThat(fromConfig.tenants().get("selected").initializationRetryInterval(), is(RETRY_INTERVAL));
        assertThat(OidcProviderConfig.builder().from(fromConfig).buildPrototype().tenants(), is(fromConfig.tenants()));
    }

    @Test
    void invalidRootRetryIntervalsAreValidatedLikeTenantIntervals() {
        for (Duration interval : List.of(Duration.ZERO, Duration.ofSeconds(-1))) {
            IllegalArgumentException fromBuilder = assertThrows(IllegalArgumentException.class,
                    () -> OidcProviderConfig.builder().initializationRetryInterval(interval).buildPrototype());
            IllegalArgumentException fromConfig = assertThrows(IllegalArgumentException.class,
                    () -> OidcProviderConfig.create(config(Map.of("initialization-retry-interval", interval.toString()))));

            assertThat(fromBuilder.getMessage(), is("initialization-retry-interval must be positive"));
            assertThat(fromConfig.getMessage(), is(fromBuilder.getMessage()));
        }
    }

    @Test
    void runtimeTokenExchangeLimiterUsesTheRootConfiguredLimit() {
        OidcProviderConfig provider = OidcProviderConfig.builder()
                .tokenExchangeRemoteWork(work -> work.maxConcurrent(1).maxQueued(0).admissionTimeout(Duration.ZERO))
                .buildPrototype();
        OidcTenantContext context = OidcTenantRuntimeRegistry.create(provider).tenantContext("default").orElseThrow();
        try {
            assertThat(context.ready(), is(true));
            OidcRemoteWorkLimiter limiter = context.tokenExchangeRemoteWorkLimiter();
            try (var _ = limiter.acquireActive().orElseThrow()) {
                var excess = limiter.acquireActive();
                try {
                    assertThat(excess.isEmpty(), is(true));
                    assertThat(limiter.activeCount(), is(1));
                } finally {
                    excess.ifPresent(OidcRemoteWorkLimiter.Permit::close);
                }
            }
            try (var _ = limiter.acquireActive().orElseThrow()) {
                assertThat(limiter.activeCount(), is(1));
            }
            assertThat(limiter.activeCount(), is(0));
        } finally {
            if (context.ready()) {
                context.webClient().closeResource();
            }
        }
    }

    private static void assertTenantOptions(OidcTenantConfig actual, OidcTenantConfig expected) {
        // WebClient includes separately constructed service instances, so compare the configured transport values.
        assertThat(actual.webClient().connectTimeout(), is(expected.webClient().connectTimeout()));
        assertThat(actual.webClient().readTimeout(), is(expected.webClient().readTimeout()));
        assertThat(OidcTenantConfig.builder().from(actual).webClient(expected.webClient()).buildPrototype(), is(expected));
    }

    private static Config config(Map<String, String> values) {
        return Config.builder().disableEnvironmentVariablesSource().disableSystemPropertiesSource()
                .sources(ConfigSources.create(values)).build();
    }
}
