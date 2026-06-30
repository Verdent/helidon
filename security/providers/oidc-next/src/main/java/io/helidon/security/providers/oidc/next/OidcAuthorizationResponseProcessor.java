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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import io.helidon.common.uri.UriQuery;
import io.helidon.http.SetCookie;

final class OidcAuthorizationResponseProcessor {
    private static final String CODE_PARAM = "code";
    private static final String STATE_PARAM = "state";
    private static final String ISS_PARAM = "iss";
    private static final String ERROR_PARAM = "error";
    private static final String ERROR_DESCRIPTION_PARAM = "error_description";
    private static final String ERROR_URI_PARAM = "error_uri";

    private final OidcProviderConfig config;
    private final OidcTenantRuntimeRegistry tenantRuntimeRegistry;

    OidcAuthorizationResponseProcessor(OidcProviderConfig config, OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        this.config = Objects.requireNonNull(config);
        this.tenantRuntimeRegistry = Objects.requireNonNull(tenantRuntimeRegistry);
    }

    OidcAuthorizationResponseResult process(UriQuery parameters,
                                            Map<String, List<String>> cookies,
                                            URI redirectionEndpointUri,
                                            Instant now) {
        Objects.requireNonNull(parameters);
        Map<String, List<String>> responseCookies = Map.copyOf(Objects.requireNonNull(cookies));
        Objects.requireNonNull(redirectionEndpointUri);
        Objects.requireNonNull(now);

        Optional<ParameterValue> stateValue = singleParameter(parameters, STATE_PARAM);
        if (stateValue.isEmpty()) {
            return OidcAuthorizationResponseResult.invalid("Authorization Response state is missing", List.of());
        }
        if (stateValue.orElseThrow().invalid()) {
            return OidcAuthorizationResponseResult.invalid("Authorization Response state must appear exactly once",
                                                           List.of());
        }

        String returnedState = stateValue.orElseThrow().value();
        Optional<ResolvedAuthenticationRequest> resolvedRequest = resolveAuthenticationRequest(returnedState,
                                                                                                responseCookies);
        if (resolvedRequest.isEmpty()) {
            return OidcAuthorizationResponseResult.invalid("Authentication Request state cookie is missing or invalid",
                                                           List.of());
        }

        ResolvedAuthenticationRequest request = resolvedRequest.orElseThrow();
        String tenantId = request.tenantId();
        OidcAuthenticationRequestState state = request.state();
        OidcCookieStateHandler cookieStateHandler = request.cookieStateHandler();
        List<SetCookie> stateRemovalCookie = List.of(cookieStateHandler.removeAuthenticationRequestCookie());

        /*
         * Spec: RFC 6749, 4.1.2 Authorization Response
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2
         * Quote: "`state` REQUIRED if the `state` parameter was present in the client authorization request. The exact
         * value received from the client."
         */
        if (!state.state().equals(returnedState)) {
            return OidcAuthorizationResponseResult.invalid(
                    "Authorization Response state does not match Authentication Request state",
                    stateRemovalCookie);
        }
        if (now.isAfter(state.expiresAt())) {
            return OidcAuthorizationResponseResult.invalid("Authentication Request state has expired", stateRemovalCookie);
        }
        if (!redirectionEndpointMatches(redirectionEndpointUri, state.redirectionEndpointUri())) {
            return OidcAuthorizationResponseResult.invalid(
                    "Authorization Response Redirection Endpoint does not match Authentication Request state",
                    stateRemovalCookie);
        }
        Optional<OidcTenantContext> tenantContext = tenantRuntimeRegistry.tenantContext(tenantId)
                .filter(OidcTenantContext::ready);
        if (tenantContext.isEmpty()) {
            return OidcAuthorizationResponseResult.invalid("Authentication Request tenant is unavailable",
                                                           stateRemovalCookie);
        }
        OidcTenantContext readyTenant = tenantContext.orElseThrow();
        Optional<OidcAuthorizationResponseResult> issuerFailure = validateIssuer(parameters,
                                                                                state,
                                                                                readyTenant,
                                                                                stateRemovalCookie);
        if (issuerFailure.isPresent()) {
            return issuerFailure.orElseThrow();
        }

        Optional<ParameterValue> code = singleParameter(parameters, CODE_PARAM);
        Optional<ParameterValue> error = singleParameter(parameters, ERROR_PARAM);
        if (code.filter(ParameterValue::invalid).isPresent()) {
            return OidcAuthorizationResponseResult.invalid("Authorization Response code must appear exactly once",
                                                           stateRemovalCookie);
        }
        if (error.filter(ParameterValue::invalid).isPresent()) {
            return OidcAuthorizationResponseResult.invalid("Authorization Response error must appear exactly once",
                                                           stateRemovalCookie);
        }
        if (code.filter(ParameterValue::valid).isPresent() && error.filter(ParameterValue::valid).isPresent()) {
            return OidcAuthorizationResponseResult.invalid("Authorization Response cannot contain both code and error",
                                                           stateRemovalCookie);
        }
        if (error.filter(ParameterValue::valid).isPresent()) {
            Optional<ParameterValue> errorDescription = singleParameter(parameters, ERROR_DESCRIPTION_PARAM);
            Optional<ParameterValue> errorUri = singleParameter(parameters, ERROR_URI_PARAM);
            if (errorDescription.filter(ParameterValue::invalid).isPresent()) {
                return OidcAuthorizationResponseResult.invalid(
                        "Authorization Response error_description must appear exactly once",
                        stateRemovalCookie);
            }
            if (errorUri.filter(ParameterValue::invalid).isPresent()) {
                return OidcAuthorizationResponseResult.invalid(
                        "Authorization Response error_uri must appear exactly once",
                        stateRemovalCookie);
            }
            /*
             * Spec: RFC 6749, 4.1.2.1 Error Response
             * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1
             * Quote: "`error` REQUIRED. A single ASCII error code."
             * Quote: "`state` REQUIRED if the `state` parameter was present in the client authorization request. The
             * exact value received from the client."
             * Quote: "Values for the `error` parameter MUST NOT include characters outside the set %x20-21 /
             * %x23-5B / %x5D-7E."
             * Quote: "Values for the `error_uri` parameter MUST conform to the URI-reference syntax and thus MUST NOT
             * include characters outside the set %x21 / %x23-5B / %x5D-7E."
             */
            String errorValue = error.orElseThrow().value();
            if (!OidcOAuthErrorFields.validError(errorValue)) {
                return OidcAuthorizationResponseResult.invalid(
                        "Authorization Response error contains invalid characters",
                        stateRemovalCookie);
            }
            Optional<String> errorDescriptionValue = errorDescription.map(ParameterValue::value);
            if (errorDescriptionValue.filter(value -> !OidcOAuthErrorFields.validErrorDescription(value)).isPresent()) {
                return OidcAuthorizationResponseResult.invalid(
                        "Authorization Response error_description contains invalid characters",
                        stateRemovalCookie);
            }
            Optional<String> errorUriValue = errorUri.map(ParameterValue::value);
            if (errorUriValue.filter(value -> !OidcOAuthErrorFields.validErrorUri(value)).isPresent()) {
                return OidcAuthorizationResponseResult.invalid(
                        "Authorization Response error_uri is invalid",
                        stateRemovalCookie);
            }
            return OidcAuthorizationResponseResult.authorizationError(errorValue,
                                                                      errorDescriptionValue.orElse(null),
                                                                      readyTenant,
                                                                      state,
                                                                      stateRemovalCookie);
        }
        if (code.filter(ParameterValue::valid).isEmpty()) {
            return OidcAuthorizationResponseResult.invalid("Authorization Response code is missing", stateRemovalCookie);
        }
        /*
         * Spec: RFC 6749, 4.1.2 Authorization Response
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2
         * Quote: "`code` REQUIRED. The authorization code generated by the authorization server."
         * Quote: "`state` REQUIRED if the `state` parameter was present in the client authorization request. The exact
         * value received from the client."
         */
        return OidcAuthorizationResponseResult.validated(code.orElseThrow().value(),
                                                         readyTenant,
                                                         state,
                                                         stateRemovalCookie);
    }

    private Optional<ResolvedAuthenticationRequest> resolveAuthenticationRequest(String returnedState,
                                                                                  Map<String, List<String>> cookies) {
        Optional<OidcAuthorizationState> authorizationState = OidcAuthorizationState.parse(returnedState);
        if (authorizationState.isEmpty()) {
            return Optional.empty();
        }
        String tenantId = authorizationState.orElseThrow().routedTenantId();
        OidcTenantConfig tenantConfig = config.tenants().get(tenantId);
        if (tenantConfig == null
                || !tenantConfig.enabled()
                || tenantConfig.authorizationCode().filter(OidcAuthorizationCodeConfig::enabled).isEmpty()) {
            return Optional.empty();
        }

        OidcCookieStateHandler cookieStateHandler = OidcCookieStateHandler.create(tenantConfig.cookies());
        String cookieName = cookieStateHandler.cookieConfig().authenticationRequestCookieName();
        List<String> stateCookies = cookies.getOrDefault(cookieName, List.of());
        if (stateCookies.size() != 1) {
            return Optional.empty();
        }
        return cookieStateHandler.decodeAuthenticationRequestState(stateCookies.getFirst())
                .filter(state -> tenantId.equals(state.tenantId()))
                .map(state -> new ResolvedAuthenticationRequest(tenantId, cookieStateHandler, state));
    }

    private Optional<OidcAuthorizationResponseResult> validateIssuer(UriQuery parameters,
                                                                     OidcAuthenticationRequestState state,
                                                                     OidcTenantContext tenantContext,
                                                                     List<SetCookie> stateRemovalCookie) {
        Optional<ParameterValue> issuer = singleParameter(parameters, ISS_PARAM);
        if (issuer.filter(ParameterValue::invalid).isPresent()) {
            return Optional.of(OidcAuthorizationResponseResult.invalid(
                    "Authorization Response iss must appear exactly once",
                    stateRemovalCookie));
        }
        /*
         * Spec: RFC 9207, 2.4 Validating the Issuer Identifier
         * https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4
         * Quote: "Clients that support this specification MUST extract the value of the `iss` parameter from
         * authorization responses they receive if the parameter is present."
         * Quote: "This comparison MUST use simple string comparison as defined in Section 6.2.1 of RFC3986."
         * Quote: "Clients MUST reject authorization responses without the `iss` parameter from authorization servers
         * that do support the parameter according to the client's configuration."
         */
        if (issuer.filter(ParameterValue::valid).isPresent()) {
            String issuerValue = issuer.orElseThrow().value();
            if (!state.expectedIssuer().equals(issuerValue)) {
                return Optional.of(OidcAuthorizationResponseResult.invalid(
                        "Authorization Response iss does not match Authentication Request issuer",
                        stateRemovalCookie));
            }
            return Optional.empty();
        }
        if (tenantContext.metadata().authorizationResponseIssuerParameterSupported()) {
            return Optional.of(OidcAuthorizationResponseResult.invalid("Authorization Response iss is missing",
                                                                       stateRemovalCookie));
        }
        return Optional.empty();
    }

    private Optional<ParameterValue> singleParameter(UriQuery parameters, String name) {
        List<String> values = parameters.all(name, List::of);
        if (values.isEmpty()) {
            return Optional.empty();
        }
        if (values.size() > 1 || values.getFirst().isEmpty()) {
            return Optional.of(ParameterValue.invalidParameter());
        }
        return Optional.of(ParameterValue.present(values.getFirst()));
    }

    private boolean redirectionEndpointMatches(URI callbackUri, URI expectedUri) {
        if (!OidcUri.sameOrigin(callbackUri, expectedUri)
                || !Objects.equals(OidcUri.path(callbackUri), OidcUri.path(expectedUri))) {
            return false;
        }

        UriQuery expectedQuery = UriQuery.create(expectedUri);
        UriQuery callbackQuery = UriQuery.create(callbackUri);
        for (String name : expectedQuery.names()) {
            if (!callbackQuery.all(name, List::of).equals(expectedQuery.all(name))) {
                return false;
            }
        }
        return true;
    }

    private record ResolvedAuthenticationRequest(String tenantId,
                                                 OidcCookieStateHandler cookieStateHandler,
                                                 OidcAuthenticationRequestState state) {
    }

    private record ParameterValue(Optional<String> text) {
        ParameterValue {
            text = Objects.requireNonNull(text);
        }

        private static ParameterValue present(String value) {
            return new ParameterValue(Optional.of(value));
        }

        private static ParameterValue invalidParameter() {
            return new ParameterValue(Optional.empty());
        }

        private String value() {
            return text.orElseThrow();
        }

        private boolean invalid() {
            return text.isEmpty();
        }

        private boolean valid() {
            return text.isPresent();
        }
    }
}
