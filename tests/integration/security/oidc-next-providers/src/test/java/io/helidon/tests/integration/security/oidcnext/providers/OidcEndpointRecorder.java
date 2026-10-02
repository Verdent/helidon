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
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.common.parameters.Parameters;
import io.helidon.http.HeaderNames;
import io.helidon.http.Status;
import io.helidon.json.JsonObject;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webserver.WebServer;

final class OidcEndpointRecorder implements AutoCloseable {
    private final List<Exchange> exchanges = new CopyOnWriteArrayList<>();
    private final AtomicInteger received = new AtomicInteger();
    private final AtomicReference<RuntimeException> failure = new AtomicReference<>();
    private final WebClient client;
    private final WebServer server;

    OidcEndpointRecorder(IdpAdapter adapter, URI nativeEndpoint) {
        client = WebClient.builder().from(adapter.webClient()).servicesDiscoverServices(false).build();
        try {
            server = WebServer.builder().host("127.0.0.1").port(0).tls(IdpResources.serverTls())
                    .routing(routing -> routing.post("/token", (request, response) -> {
                        received.incrementAndGet();
                        try {
                            Parameters form = request.content().as(Parameters.class);
                            try (HttpClientResponse nativeResponse = client.post().uri(nativeEndpoint)
                                    .header(HeaderNames.AUTHORIZATION,
                                            request.headers().first(HeaderNames.AUTHORIZATION).orElseThrow())
                                    .submit(form)) {
                                JsonObject body = nativeResponse.as(JsonObject.class);
                                exchanges.add(new Exchange(form.first("grant_type").orElse(""),
                                                           Set.copyOf(form.names()), nativeResponse.status(), body));
                                for (var name : List.of(HeaderNames.CONTENT_TYPE, HeaderNames.CACHE_CONTROL,
                                                        HeaderNames.PRAGMA, HeaderNames.WWW_AUTHENTICATE)) {
                                    nativeResponse.headers().first(name).ifPresent(value -> response.headers().set(name, value));
                                }
                                response.status(nativeResponse.status()).send(body);
                            }
                        } catch (RuntimeException e) {
                            failure.set(e);
                            throw e;
                        }
                    })).build().start();
        } catch (RuntimeException e) {
            client.closeResource();
            throw e;
        }
    }

    URI uri() {
        return URI.create("https://localhost:" + server.port() + "/token");
    }

    List<Exchange> exchanges() {
        return List.copyOf(exchanges);
    }

    String diagnostics() {
        return "OIDC recorder received " + received.get() + " requests; native exchanges: "
                + exchanges.stream().map(exchange -> exchange.grantType() + " " + exchange.status()).toList()
                + "; failure: " + failure.get();
    }

    @Override
    public void close() {
        try {
            server.stop();
        } finally {
            client.closeResource();
        }
    }

    record Exchange(String grantType, Set<String> parameterNames, Status status, JsonObject response) {
    }
}
