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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import io.helidon.common.uri.UriQuery;
import io.helidon.http.SetCookie;

final class OidcAuthorizationResponseProcessor {
    private static final String CODE_PARAM = "code";
    private static final String STATE_PARAM = "state";
    private static final String ERROR_PARAM = "error";
    private static final String ERROR_DESCRIPTION_PARAM = "error_description";
    private static final String ERROR_URI_PARAM = "error_uri";

    private final OidcProviderConfig config;
    private final OidcTenantRuntimeRegistry tenantRuntimeRegistry;

    private OidcAuthorizationResponseProcessor(OidcProviderConfig config,
                                               OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        this.config = Objects.requireNonNull(config);
        this.tenantRuntimeRegistry = Objects.requireNonNull(tenantRuntimeRegistry);
    }

    static OidcAuthorizationResponseProcessor create(OidcProviderConfig config,
                                                     OidcTenantRuntimeRegistry tenantRuntimeRegistry) {
        return new OidcAuthorizationResponseProcessor(config, tenantRuntimeRegistry);
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

        List<StoredAuthenticationRequestState> storedStates = authenticationRequestStates(responseCookies);
        if (storedStates.isEmpty()) {
            return OidcAuthorizationResponseResult.invalid("Authentication Request state cookie is missing or invalid",
                                                           List.of());
        }
        if (storedStates.size() > 1) {
            return OidcAuthorizationResponseResult.invalid("Authentication Request state is ambiguous",
                                                           stateRemovalCookies(storedStates));
        }

        StoredAuthenticationRequestState storedState = storedStates.get(0);
        OidcAuthenticationRequestState state = storedState.state();
        List<SetCookie> stateRemovalCookie = List.of(storedState.tenantContext()
                                                             .cookieStateHandler()
                                                             .removeAuthenticationRequestCookie());

        /*
         * Spec: RFC 6749, 4.1.2 Authorization Response
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2
         * Quote: "The exact value received from the client".
         */
        if (!state.state().equals(stateValue.orElseThrow().value())) {
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
        if (code.filter(ParameterValue::present).isPresent() && error.filter(ParameterValue::present).isPresent()) {
            return OidcAuthorizationResponseResult.invalid("Authorization Response cannot contain both code and error",
                                                           stateRemovalCookie);
        }
        if (error.filter(ParameterValue::present).isPresent()) {
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
             * Quotes: "`error` REQUIRED"; "`state` REQUIRED if a `state` parameter was present".
             */
            return OidcAuthorizationResponseResult.authorizationError(error.orElseThrow().value(),
                                                                      errorDescription.map(ParameterValue::value)
                                                                              .orElse(null),
                                                                      storedState.tenantContext(),
                                                                      state,
                                                                      stateRemovalCookie);
        }
        if (code.filter(ParameterValue::present).isEmpty()) {
            return OidcAuthorizationResponseResult.invalid("Authorization Response code is missing", stateRemovalCookie);
        }
        /*
         * Spec: RFC 6749, 4.1.2 Authorization Response
         * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2
         * Quotes: "`code` REQUIRED"; "`state` REQUIRED if the `state` parameter was present".
         */
        return OidcAuthorizationResponseResult.validated(code.orElseThrow().value(),
                                                         storedState.tenantContext(),
                                                         state,
                                                         stateRemovalCookie);
    }

    private List<StoredAuthenticationRequestState> authenticationRequestStates(Map<String, List<String>> cookies) {
        List<StoredAuthenticationRequestState> states = new ArrayList<>();
        for (String tenantId : config.tenants().keySet()) {
            Optional<OidcTenantContext> tenantContext = tenantRuntimeRegistry.tenantContext(tenantId)
                    .filter(OidcTenantContext::ready);
            if (tenantContext.isEmpty()) {
                continue;
            }

            OidcTenantContext readyTenant = tenantContext.orElseThrow();
            OidcCookieStateHandler cookieStateHandler = readyTenant.cookieStateHandler();
            String cookieName = cookieStateHandler.cookieConfig().authenticationRequestCookieName();
            for (String cookieValue : cookies.getOrDefault(cookieName, List.of())) {
                cookieStateHandler.decodeAuthenticationRequestState(cookieValue)
                        .filter(state -> readyTenant.tenantId().equals(state.tenantId()))
                        .map(state -> new StoredAuthenticationRequestState(readyTenant, state))
                        .ifPresent(states::add);
            }
        }
        return states;
    }

    private List<SetCookie> stateRemovalCookies(List<StoredAuthenticationRequestState> states) {
        return states.stream()
                .map(StoredAuthenticationRequestState::tenantContext)
                .map(OidcTenantContext::cookieStateHandler)
                .map(OidcCookieStateHandler::removeAuthenticationRequestCookie)
                .toList();
    }

    private Optional<ParameterValue> singleParameter(UriQuery parameters, String name) {
        List<String> values = parameters.all(name, List::of);
        if (values.isEmpty()) {
            return Optional.empty();
        }
        if (values.size() > 1 || values.get(0).isEmpty()) {
            return Optional.of(ParameterValue.invalidParameter());
        }
        return Optional.of(ParameterValue.present(values.get(0)));
    }

    private boolean redirectionEndpointMatches(URI callbackUri, URI expectedUri) {
        if (!Objects.equals(normalize(callbackUri.getScheme()), normalize(expectedUri.getScheme()))
                || !Objects.equals(normalize(callbackUri.getHost()), normalize(expectedUri.getHost()))
                || effectivePort(callbackUri) != effectivePort(expectedUri)
                || !Objects.equals(path(callbackUri), path(expectedUri))) {
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

    private int effectivePort(URI uri) {
        int port = uri.getPort();
        if (port != -1) {
            return port;
        }
        String scheme = uri.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            return 443;
        }
        if ("http".equalsIgnoreCase(scheme)) {
            return 80;
        }
        return -1;
    }

    private String path(URI uri) {
        String path = uri.getPath();
        if (path == null || path.isEmpty()) {
            return "/";
        }
        return path;
    }

    private String normalize(String value) {
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }

    private record StoredAuthenticationRequestState(OidcTenantContext tenantContext,
                                                    OidcAuthenticationRequestState state) {
    }

    private record ParameterValue(String value, boolean valid) {
        private static ParameterValue present(String value) {
            return new ParameterValue(value, true);
        }

        private static ParameterValue invalidParameter() {
            return new ParameterValue(null, false);
        }

        private boolean present() {
            return valid;
        }

        private boolean invalid() {
            return !valid;
        }
    }
}
