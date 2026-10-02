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

package io.helidon.tests.integration.security.oidcnext.providers;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.SetCookie;
import io.helidon.json.JsonObject;
import io.helidon.webclient.api.HttpClientRequest;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;

final class TestBrowser implements AutoCloseable {
    private final WebClient client;
    private final Map<CookieKey, StoredCookie> cookies = new LinkedHashMap<>();

    TestBrowser(WebClientConfig config) {
        client = WebClient.builder().from(config).followRedirects(false).build();
    }

    HttpClientResponse get(URI uri) throws Exception {
        HttpClientRequest request = client.get().uri(uri);
        addCookies(uri, request);
        HttpClientResponse response = request.request();
        remember(uri, response);
        return response;
    }

    HttpClientResponse post(URI uri, Parameters form) throws Exception {
        HttpClientRequest request = client.post().uri(uri)
                .header(HeaderNames.ORIGIN, uri.getScheme() + "://" + uri.getAuthority());
        addCookies(uri, request);
        HttpClientResponse response = request.submit(form);
        remember(uri, response);
        return response;
    }

    JsonObject postJson(URI uri, JsonObject body) throws Exception {
        HttpClientRequest request = client.post().uri(uri)
                .header(HeaderNames.ORIGIN, uri.getScheme() + "://" + uri.getAuthority());
        addCookies(uri, request);
        try (HttpClientResponse response = request.submit(body)) {
            remember(uri, response);
            if (response.status().code() != 200) {
                throw new IllegalStateException("Provider JSON request failed: " + uri.getPath() + ": "
                                                        + response.status() + " " + response.as(String.class));
            }
            JsonObject result = response.as(JsonObject.class);
            if (!result.stringValue("status").orElse("").equals("OK")) {
                throw new IllegalStateException("Provider JSON operation failed: " + uri.getPath() + ": " + result);
            }
            return result;
        }
    }

    @Override
    public void close() {
        client.closeResource();
    }

    private void addCookies(URI uri, HttpClientRequest request) {
        Instant now = Instant.now();
        String path = uri.getPath().isEmpty() ? "/" : uri.getPath();
        String header = cookies.entrySet().stream().filter(entry -> {
            CookieKey key = entry.getKey();
            StoredCookie cookie = entry.getValue();
            boolean domain = uri.getHost().equals(key.domain())
                    || !cookie.hostOnly() && uri.getHost().endsWith("." + key.domain());
            boolean matchingPath = path.equals(key.path()) || path.startsWith(key.path())
                    && (key.path().endsWith("/") || path.charAt(key.path().length()) == '/');
            return domain && matchingPath && cookie.expiresAt().isAfter(now)
                    && (!cookie.secure() || uri.getScheme().equals("https"));
        }).map(entry -> entry.getKey().name() + "=" + entry.getValue().value()).collect(Collectors.joining("; "));
        if (!header.isEmpty()) {
            request.header(HeaderNames.COOKIE, header);
        }
    }

    private void remember(URI uri, HttpClientResponse response) {
        if (response.headers().contains(HeaderNames.SET_COOKIE)) {
            for (String raw : response.headers().get(HeaderNames.SET_COOKIE).allValues()) {
                SetCookie cookie = SetCookie.parse(raw);
                String domain = cookie.domain().orElse(uri.getHost());
                if (domain.startsWith(".")) {
                    domain = domain.substring(1);
                }
                CookieKey key = new CookieKey(domain, cookie.path().orElse("/"), cookie.name());
                Instant expiresAt = cookie.maxAge().map(age -> Instant.now().plus(age))
                        .orElseGet(() -> cookie.expires().map(value -> value.toInstant()).orElse(Instant.MAX));
                if (expiresAt.isAfter(Instant.now())) {
                    cookies.put(key, new StoredCookie(cookie.value(), cookie.secure(), cookie.domain().isEmpty(), expiresAt));
                } else {
                    cookies.remove(key);
                }
            }
        }
    }

    private record CookieKey(String domain, String path, String name) {
    }

    private record StoredCookie(String value, boolean secure, boolean hostOnly, Instant expiresAt) {
    }
}
