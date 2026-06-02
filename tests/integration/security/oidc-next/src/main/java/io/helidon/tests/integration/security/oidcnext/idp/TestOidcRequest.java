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

package io.helidon.tests.integration.security.oidcnext.idp;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderName;
import io.helidon.http.HeaderNames;
import io.helidon.webserver.http.ServerRequest;

/**
 * Parsed OIDC test IdP request.
 */
public final class TestOidcRequest {
    private final ServerRequest rawRequest;
    private final String method;
    private final String path;
    private final Map<String, List<String>> queryParameters;
    private final Map<String, List<String>> formParameters;

    private TestOidcRequest(ServerRequest rawRequest,
                            String method,
                            String path,
                            Map<String, List<String>> queryParameters,
                            Map<String, List<String>> formParameters) {
        this.rawRequest = rawRequest;
        this.method = method;
        this.path = path;
        this.queryParameters = Map.copyOf(queryParameters);
        this.formParameters = Map.copyOf(formParameters);
    }

    static TestOidcRequest create(ServerRequest request, boolean parseForm) {
        Parameters form = parseForm ? request.content().as(Parameters.class) : Parameters.empty("form");
        return new TestOidcRequest(request,
                                   request.prologue().method().text(),
                                   request.requestedUri().path().path(),
                                   request.query().toMap(),
                                   form.toMap());
    }

    /**
     * Raw Helidon request.
     *
     * @return raw request
     */
    public ServerRequest rawRequest() {
        return rawRequest;
    }

    /**
     * HTTP method.
     *
     * @return method
     */
    public String method() {
        return method;
    }

    /**
     * Request path.
     *
     * @return path
     */
    public String path() {
        return path;
    }

    /**
     * Query parameters.
     *
     * @return query parameters
     */
    public Map<String, List<String>> queryParameters() {
        return queryParameters;
    }

    /**
     * Form parameters.
     *
     * @return form parameters
     */
    public Map<String, List<String>> formParameters() {
        return formParameters;
    }

    /**
     * First query parameter value.
     *
     * @param name parameter name
     * @return value
     */
    public Optional<String> queryParam(String name) {
        return first(queryParameters, name);
    }

    /**
     * First form parameter value.
     *
     * @param name parameter name
     * @return value
     */
    public Optional<String> formParam(String name) {
        return first(formParameters, name);
    }

    /**
     * First header value.
     *
     * @param name header name
     * @return value
     */
    public Optional<String> header(HeaderName name) {
        return rawRequest.headers().first(name);
    }

    /**
     * First header value.
     *
     * @param name header name
     * @return value
     */
    public Optional<String> header(String name) {
        return rawRequest.headers().first(HeaderNames.create(name));
    }

    /**
     * Parsed HTTP Basic credentials.
     *
     * @return credentials
     */
    public Optional<BasicCredentials> basicCredentials() {
        return header(HeaderNames.AUTHORIZATION)
                .filter(value -> value.regionMatches(true, 0, "Basic ", 0, 6))
                .map(value -> value.substring(6))
                .map(value -> new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8))
                .flatMap(value -> {
                    int delimiter = value.indexOf(':');
                    if (delimiter < 0) {
                        return Optional.empty();
                    }
                    return Optional.of(new BasicCredentials(value.substring(0, delimiter),
                                                           value.substring(delimiter + 1)));
                });
    }

    /**
     * Parsed bearer token.
     *
     * @return bearer token
     */
    public Optional<String> bearerToken() {
        return header(HeaderNames.AUTHORIZATION)
                .filter(value -> value.regionMatches(true, 0, "Bearer ", 0, 7))
                .map(value -> value.substring(7));
    }

    private static Optional<String> first(Map<String, List<String>> parameters, String name) {
        return Optional.ofNullable(parameters.get(name))
                .filter(values -> !values.isEmpty())
                .map(List::getFirst);
    }

    /**
     * Basic authentication credentials.
     *
     * @param username username
     * @param password password
     */
    public record BasicCredentials(String username, String password) {
    }
}
