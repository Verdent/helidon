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
import java.time.Instant;
import java.util.Optional;

import io.helidon.common.Errors;
import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.HeaderValues;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.security.jwt.JwtValidator;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;

final class OidcIntrospectionAccessTokenValidator implements OidcAccessTokenValidator {
    private OidcIntrospectionAccessTokenValidator() {
    }

    static OidcIntrospectionAccessTokenValidator create() {
        return new OidcIntrospectionAccessTokenValidator();
    }

    @Override
    public OidcValidationResult<OidcValidatedAccessToken> validate(String token, OidcTenantContext tenantContext) {
        Optional<URI> endpointUri = tenantContext.metadata().introspectionEndpointUri();
        OidcTenantConfig tenantConfig = tenantContext.tenantConfig();
        Optional<String> clientId = tenantConfig.clientId();
        Optional<String> clientSecret = tenantConfig.clientSecret();
        if (endpointUri.isEmpty() || clientId.isEmpty() || clientSecret.isEmpty()) {
            return OidcValidationResult.failure("Bearer Token introspection is not configured");
        }

        try (HttpClientResponse response = request(tenantContext.webClient(),
                                                   endpointUri.orElseThrow(),
                                                   token,
                                                   clientId.orElseThrow(),
                                                   clientSecret.orElseThrow())) {
            if (response.status().family() != Status.Family.SUCCESSFUL) {
                if (response.status().code() >= 500) {
                    return OidcValidationResult.failure("Bearer Token introspection endpoint is unavailable");
                }
                return OidcValidationResult.failure("Bearer Token introspection endpoint rejected the token");
            }

            return validateResponse(token, tenantContext, response);
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("Bearer Token introspection endpoint is unavailable", e);
        }
    }

    private OidcValidationResult<OidcValidatedAccessToken> validateResponse(String token,
                                                       OidcTenantContext tenantContext,
                                                       HttpClientResponse response) {
        JsonObject jsonObject;
        try {
            /*
             * Spec: RFC 7662, 2.2 Introspection Response
             * https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2
             * Quote: "The response is a JSON object".
             */
            if (!OidcHttpResponseValidation.hasJsonContentType(response)) {
                return OidcValidationResult.failure("Bearer Token introspection response is invalid");
            }
            jsonObject = response.as(JsonObject.class);
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("Bearer Token introspection response is invalid", e);
        }

        try {
            Optional<Boolean> active = jsonObject.booleanValue("active");
            if (active.isEmpty()) {
                return OidcValidationResult.failure("Bearer Token introspection response is invalid");
            }
            if (!active.orElseThrow()) {
                return OidcValidationResult.failure("Bearer Token introspection response is inactive");
            }

            OidcValidatedIntrospection validated = OidcValidatedIntrospection.create(token, jsonObject);
            OidcValidationResult<OidcValidatedAccessToken> claimValidation = validateClaims(validated, tenantContext);
            if (!claimValidation.succeeded()) {
                return claimValidation;
            }
            return OidcValidationResult.success(validated);
        } catch (RuntimeException e) {
            return OidcValidationResult.failure("Bearer Token introspection response is invalid", e);
        }
    }

    private OidcValidationResult<OidcValidatedAccessToken> validateClaims(OidcValidatedIntrospection validated,
                                                     OidcTenantContext tenantContext) {
        OidcTokenValidationConfig tokenValidation = tenantContext.tokenValidation();
        Optional<String> expectedIssuer = tenantContext.metadata().issuer().map(Object::toString);
        Optional<String> expectedAudience = tokenValidation.audience();
        Instant now = Instant.now();
        if (tokenValidation.audienceValidationEnabled() && expectedAudience.isEmpty()) {
            return OidcValidationResult.failure("Bearer Token introspection is not configured");
        }

        JwtValidator.Builder builder = JwtValidator.builder()
                .addExpirationValidator(it -> it.now(now).allowedTimeSkew(tokenValidation.clockSkew()))
                .addIssueTimeValidator(it -> it.now(now).allowedTimeSkew(tokenValidation.clockSkew()))
                .addNotBeforeValidator(it -> it.now(now).allowedTimeSkew(tokenValidation.clockSkew()));
        expectedIssuer.ifPresent(issuer -> builder.addIssuerValidator(issuer, false));
        if (tokenValidation.audienceValidationEnabled()) {
            expectedAudience.ifPresent(builder::addAudienceValidator);
        }
        Errors claimErrors = builder.build().validate(validated.jwt());
        if (!claimErrors.isValid()) {
            return OidcValidationResult.failure("Bearer Token introspection claims are invalid");
        }

        if (OidcSubjectMapper.principalId(validated.claims(), tenantContext.subjectMapping()).isEmpty()) {
            return OidcValidationResult.failure("Bearer Token introspection response has no principal claim");
        }
        if (validated.tokenType()
                .filter(tokenType -> !"bearer".equalsIgnoreCase(tokenType))
                .isPresent()) {
            return OidcValidationResult.failure("Bearer Token introspection claims are invalid");
        }
        return OidcValidationResult.success(validated);
    }

    private HttpClientResponse request(WebClient webClient,
                                       URI endpointUri,
                                       String token,
                                       String clientId,
                                       String clientSecret) {
        Parameters form = Parameters.builder("oidc-introspection-form")
                .add("token", token)
                .add("token_type_hint", "access_token")
                .build();
        return webClient.post()
                .uri(endpointUri)
                .followRedirects(false)
                .header(HeaderValues.ACCEPT_JSON)
                .header(HeaderNames.AUTHORIZATION,
                        OidcClientAuthenticationSupport.basicAuthorization(clientId, clientSecret))
                .header(HeaderValues.CACHE_NO_CACHE)
                .header(HeaderNames.CONTENT_TYPE, "application/x-www-form-urlencoded")
                .submit(form);
    }

}
