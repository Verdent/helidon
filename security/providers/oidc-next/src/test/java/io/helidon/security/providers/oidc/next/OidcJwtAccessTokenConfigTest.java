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

import java.net.URI;
import java.util.List;
import java.util.Map;

import io.helidon.config.Config;
import io.helidon.config.ConfigSources;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcJwtAccessTokenConfigTest {
    @Test
    void defaultTokenValidationRetainsRfc9068Profile() {
        OidcJwtAccessTokenConfig config = OidcTokenValidationConfig.create().jwt();

        assertThat(config.profile(), is(OidcJwtAccessTokenProfile.RFC_9068));
        assertThat(config.allowedTypes(), is(List.of("at+jwt", "application/at+jwt")));
        assertThat(config.requiredClaims(), is(List.of()));
        assertThat(config.requiredStringClaims(), is(Map.of()));
    }

    @Test
    void tenantConfigurationAndBuilderSelectTheSameCustomLayout() {
        Config source = Config.builder()
                .sources(ConfigSources.create(Map.ofEntries(
                        Map.entry("issuer", "https://issuer.example"),
                        Map.entry("protected-resource.token-validation.method", "JWT"),
                        Map.entry("protected-resource.token-validation.audience", "api"),
                        Map.entry("protected-resource.token-validation.jwt.profile", "CUSTOM"),
                        Map.entry("protected-resource.token-validation.jwt.allowed-types.0", "JWT"),
                        Map.entry("protected-resource.token-validation.jwt.allowed-types.1", "at+jwt"),
                        Map.entry("protected-resource.token-validation.jwt.required-claims.0", "sub"),
                        Map.entry("protected-resource.token-validation.jwt.required-claims.1", "azp"),
                        Map.entry("protected-resource.token-validation.jwt.required-string-claims.typ", "Bearer"))))
                .build();
        OidcProviderConfig fromConfig = OidcProviderConfig.create(source);
        OidcProviderConfig fromBuilder = OidcProviderConfig.builder()
                .issuer("https://issuer.example")
                .protectedResource(resource -> resource.tokenValidation(validation -> validation
                        .method(OidcTokenValidationMethod.JWT)
                        .audience("api")
                        .jwt(jwt -> jwt.profile(OidcJwtAccessTokenProfile.CUSTOM)
                                .allowedTypes(List.of("JWT", "at+jwt"))
                                .requiredClaims(List.of("sub", "azp"))
                                .putRequiredStringClaim("typ", "Bearer"))))
                .buildPrototype();

        OidcTokenValidationConfig configured = fromConfig.tenants().get("default")
                .protectedResource().orElseThrow().tokenValidation();
        OidcTokenValidationConfig built = fromBuilder.tenants().get("default")
                .protectedResource().orElseThrow().tokenValidation();
        assertThat(configured, is(built));
        assertThat(configured.jwt().requiredStringClaims(), is(Map.of("typ", "Bearer")));
    }

    @Test
    void rfc9068ProfileCannotAllowGenericJwtTypes() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> OidcJwtAccessTokenConfig.builder().allowedTypes(List.of("JWT")).buildPrototype());

        assertThat(exception.getMessage(), containsString("unless token-validation.jwt.profile is CUSTOM"));
    }

    @Test
    void customGenericJwtTypesRequireAnAccessTokenMarker() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> OidcJwtAccessTokenConfig.builder()
                        .profile(OidcJwtAccessTokenProfile.CUSTOM)
                        .allowedTypes(List.of("JWT"))
                        .requiredClaims(List.of("sub", "azp"))
                        .buildPrototype());

        assertThat(exception.getMessage(), containsString("required-string-claims must identify access tokens"));
    }

    @Test
    void emptyHeaderTypesAreRejected() {
        assertThrows(IllegalArgumentException.class,
                     () -> OidcJwtAccessTokenConfig.builder().allowedTypes(List.of()).buildPrototype());
    }

    @Test
    void blankAndPaddedLayoutValuesAreRejected() {
        for (String value : List.of("", " ", " value", "value ")) {
            assertThrows(IllegalArgumentException.class,
                         () -> OidcJwtAccessTokenConfig.builder().allowedTypes(List.of(value)).buildPrototype());
            assertThrows(IllegalArgumentException.class,
                         () -> OidcJwtAccessTokenConfig.builder().addRequiredClaim(value).buildPrototype());
            assertThrows(IllegalArgumentException.class,
                         () -> OidcJwtAccessTokenConfig.builder().putRequiredStringClaim(value, "Bearer").buildPrototype());
            assertThrows(IllegalArgumentException.class,
                         () -> OidcJwtAccessTokenConfig.builder().putRequiredStringClaim("typ", value).buildPrototype());
        }
    }

    @Test
    void customProfileRequiresJwtValidationMethod() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> OidcTenantConfig.builder()
                        .issuer("https://issuer.example")
                        .endpoints(endpoints -> endpoints
                                .introspectionEndpointUri(URI.create("https://issuer.example/introspect")))
                        .protectedResource(resource -> resource.tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.INTROSPECTION)
                                .jwt(jwt -> jwt.profile(OidcJwtAccessTokenProfile.CUSTOM))))
                        .buildPrototype());

        assertThat(exception.getMessage(), containsString("CUSTOM requires token-validation.method JWT"));
    }

    @Test
    void customProfileRequiresAudienceValidation() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> OidcTenantConfig.builder()
                        .issuer("https://issuer.example")
                        .protectedResource(resource -> resource.tokenValidation(validation -> validation
                                .method(OidcTokenValidationMethod.JWT)
                                .audienceValidationEnabled(false)
                                .jwt(jwt -> jwt.profile(OidcJwtAccessTokenProfile.CUSTOM))))
                        .buildPrototype());

        assertThat(exception.getMessage(), containsString("CUSTOM requires audience validation"));
    }
}
