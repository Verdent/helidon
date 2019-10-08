/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
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
package io.helidon.rest.client.example.basic;

import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import io.helidon.config.Config;
import io.helidon.metrics.RegistryFactory;
import io.helidon.metrics.rest.client.ClientMetrics;
import io.helidon.security.Security;
import io.helidon.security.rest.client.ClientSecurity;
import io.helidon.tracing.rest.client.ClientTracing;
import io.helidon.webclient.Proxy;
import io.helidon.webclient.WebClient;

import io.opentracing.SpanContext;
import org.eclipse.microprofile.metrics.MetricRegistry;

/**
 * A standalone REST client.
 */
public class StandaloneClientExample {
    private static final Logger LOGGER = Logger.getLogger(StandaloneClientExample.class.getName());

    // todo how to handle entity processors (e.g. how to add JSON-P, JSON-B support)
    public static void main(String[] args) throws ExecutionException, InterruptedException {
        /*
         * Prepare helidon stuff
         */
        Config config = Config.create();
        Security security = Security.create(config.get("security"));
        RegistryFactory seMetricFactory = RegistryFactory.create(config);


        /*
         * Client must be thread safe (basically a pre-configured container)
         */
        WebClient client = WebClient.builder()
                // default configuration of client metrics
                // REQUIRES: metrics registry configured on request context (injected by MetricsSupport)
                .register(ClientMetrics.create(seMetricFactory, seMetricFactory.getRegistry(MetricRegistry.Type.APPLICATION)))
                // default configuration of tracing
                // REQUIRES: span context configured on request context (injected by future TracingSupport)
                .register(ClientTracing.create())
                // default configuration of client security - invokes outbound provider(s) and updates headers
                // REQUIRES: security and security context configured on request context (injected by WebSecurity)
                .register(ClientSecurity.create(security))
                .proxy(Proxy.builder()
                               .type(Proxy.ProxyType.HTTP)
                               .host("proxy-host")
                               .port(80)
                               .addNoProxy("localhost")
                               .addNoProxy(".oracle.com")
                               .build())
                .build();

        SpanContext spanContext = null;

        /*
         * Each request is created using a builder like fluent api
         */
        //        CompletionStage<ClientResponse> response = client.put()
        //                .uri("http://localhost:8080/greeting")
        //                // parent span
        //                .property(ClientTracing.PARENT_SPAN, spanContext)
        //                // override tracing span
        //                .property(ClientTracing.SPAN_NAME, "myspan")
        //                // override metric name
        //                .property(ClientMetrics.ENDPOINT_NAME, "aServiceName")
        //                .property(ClientSecurity.PROVIDER_NAME, "http-basic-auth")
        //                // override security
        //                .property("io.helidon.security.outbound.username", "aUser")
        //                // add custom header
        //                .header("MY_HEADER", "Value")
        //                // override proxy configuration of client
        //                .proxy(Proxy.noProxy())
        //                // send entity (may be a publisher of chunks)
        //                // should support forms
        //                .submit("New Hello");
        //
        //
        //        response.thenApply(ClientResponse::status)
        //                .thenAccept(System.out::println)
        //                .toCompletableFuture()
        //                .join();

        client.get()
                .uri("http://localhost:8080/greet")
                .request(String.class)
                .thenAccept(System.out::println)
                .exceptionally(throwable -> {
                    // handle client error
                    LOGGER.log(Level.SEVERE, "Failed to invoke client", throwable);
                    return null;
                })
                // this is to make sure the VM does not exit before finishing the call
                .toCompletableFuture()
                .get();
    }
}
