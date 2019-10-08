/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 */
package io.helidon.rest.client.example.webserver;

import java.nio.charset.StandardCharsets;

import javax.json.Json;
import javax.json.JsonObject;

import io.helidon.common.OptionalHelper;
import io.helidon.common.http.Http;
import io.helidon.config.Config;
import io.helidon.media.json.processing.client.ClientJsonpSupport;
import io.helidon.metrics.rest.client.ClientMetrics;
import io.helidon.security.rest.client.ClientSecurity;
import io.helidon.tracing.rest.client.ClientTracing;
import io.helidon.webclient.ClientException;
import io.helidon.webclient.ClientResponse;
import io.helidon.webclient.Proxy;
import io.helidon.webclient.WebClient;
import io.helidon.webserver.Routing;
import io.helidon.webserver.ServerRequest;
import io.helidon.webserver.ServerResponse;
import io.helidon.webserver.WebServer;

/**
 * TODO javadoc.
 */
public class WebserverClientExample {
    private static WebClient webClient;
    private static ClientJsonpSupport jsonSupport;

    public static void main(String[] args) {
        Config config = Config.create();

        jsonSupport = ClientJsonpSupport.create();

        webClient = WebClient.builder()
                // default configuration of client metrics
                // REQUIRES: metrics registry configured on request context (injected by MetricsSupport)
                .register(ClientMetrics.create())
                // default configuration of tracing
                // REQUIRES: span context configured on request context (injected by future TracingSupport)
                .register(ClientTracing.create())
                // default configuration of client security - invokes outbound provider(s) and updates headers
                // REQUIRES: security and security context configured on request context (injected by WebSecurity)
                .register(ClientSecurity.create())
                .register(jsonSupport)
                .proxy(Proxy.create(config))
                .build();

        WebServer server = WebServer.create(Routing.builder()
                                                    .get("/hello", WebserverClientExample::hello)
                                                    .post("/put", WebserverClientExample::put)
                                                    .build());

        server.start()
                .thenAccept(webServer -> System.out.println("Webserver started on http://localhost:" + server.port()));
    }

    private static void put(ServerRequest req, ServerResponse res) {
        JsonObject object = Json.createObjectBuilder()
                .add("key", "value")
                .add("anotherKey", 42)
                .build();

        webClient.put()
                .uri("http://localhost:8080/greeint")
                .context(req.context())
                // request specific handler
                .register(jsonSupport.derive(StandardCharsets.ISO_8859_1))
                .submit(object)
                // TODO maybe could live without the next line and propagate also errors
                .thenApply(ClientResponse::content)
                .thenAccept(res::send)
                .exceptionally(throwable -> handleException(res, throwable));
    }

    private static void proxyResponse(ServerRequest req, ServerResponse res) {
        webClient.get()
                .uri("http://localhost:8080/greet")
                .context(req.context())
                .request()
                .thenAccept(clientResponse -> {
                    res.headers().add("CUSTOM_RESPONSE", "HEADER");
                    res.status(clientResponse.status());
                    res.send(clientResponse.content());
                });
    }

    private static void proxyRequestAndResponse(ServerRequest req, ServerResponse res) {
        webClient.get()
                .context(req.context())
                .uri("http://localhost:8080")
                .path(req.path())
                .queryParams(req.queryParams())
                .headers(req.headers())
                .submit(req.content())
                .thenAccept(clientResponse -> {
                    res.headers().add("CUSTOM_RESPONSE", "HEADER");
                    res.status(clientResponse.status());
                    res.send(clientResponse.content());
                })
                .exceptionally(throwable -> handleException(res, throwable));

    }

    private static Void handleException(ServerResponse res, Throwable throwable) {
        if (throwable instanceof ClientException) {
            ClientException e = (ClientException) throwable;
            OptionalHelper.from(e.response())
                    .ifPresentOrElse(clientResponse -> {
                        res.status(clientResponse.status());
                        res.send(clientResponse.content());
                    }, () -> {
                        res.status(Http.Status.INTERNAL_SERVER_ERROR_500);
                        res.send();
                    });

        } else {
            // TODO log and send entity with stacktrace if in debug mode
            res.status(Http.Status.INTERNAL_SERVER_ERROR_500);
            res.send();
        }

        return null;
    }

    private static void hello(ServerRequest req, ServerResponse res) {
        webClient.get(req.context(), "http://www.google.com")
                .request()
                .thenApply(ClientResponse::content)
                .thenAccept(res::send)
                .exceptionally(throwable -> handleException(res, throwable));
    }

}
