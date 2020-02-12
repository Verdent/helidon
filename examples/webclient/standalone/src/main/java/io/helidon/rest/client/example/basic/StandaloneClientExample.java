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

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import io.helidon.config.Config;
import io.helidon.metrics.RegistryFactory;
import io.helidon.metrics.rest.client.ClientMetrics;
import io.helidon.security.Security;
import io.helidon.security.rest.client.ClientSecurity;
import io.helidon.tracing.rest.client.ClientTracing;
import io.helidon.webclient.ClientResponse;
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
    public static void main(String[] args) throws ExecutionException, InterruptedException, IOException {
        //LogManager.getLogManager().readConfiguration(StandaloneClientExample.class.getResourceAsStream("/logging.properties"));
        //LOGGER.finest("It works");
        /*
         * Prepare helidon stuff
         */
        Config config = Config.create();
        //        Config config = Config.builder().disableEnvironmentVariablesSource()
        //                .disableSystemPropertiesSource()
        //                .sources(ConfigSources.classpath("application.yaml"))
        //                .build();
        Security security = Security.create(config.get("security"));
        RegistryFactory seMetricFactory = RegistryFactory.create(config);


        /*
         * Client must be thread safe (basically a pre-configured container)
         */
        WebClient client = WebClient.builder()
                // default configuration of client metrics
                // REQUIRES: metrics registry configured on request context (injected by MetricsSupport)
// TODO               .register(ClientMetrics.create(seMetricFactory, seMetricFactory.getRegistry(MetricRegistry.Type.APPLICATION)))
                // default configuration of tracing
                // REQUIRES: span context configured on request context (injected by future TracingSupport)
                .register(ClientTracing.create())
                // default configuration of client security - invokes outbound provider(s) and updates headers
                // REQUIRES: security and security context configured on request context (injected by WebSecurity)
                .register(ClientSecurity.create(security))
                .config(config)
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

        //        client.get()
        //                .uri("http://localhost:8080/greet")
        //                .header("test", "testValue")
        //                .queryParam("query", "value")
        //                .queryParam("query2", "value2", "value3")
        //                .request(String.class)
        //                .thenAccept(System.out::println)
        //                .exceptionally(throwable -> {
        //                    // handle client error
        //                    LOGGER.log(Level.SEVERE, "Failed to invoke client", throwable);
        //                    return null;
        //                })
        //                // this is to make sure the VM does not exit before finishing the call
        //                .toCompletableFuture()
        //                .get();

                client.get()
                                .uri("http://www.google.com/search")
                                .queryParam("q", "test")
                                .request(String.class)
                                .thenAccept(System.out::println)
                                .thenCompose(nothing -> client.get()
                                        .uri("https://www.google.com/search")
                                        .queryParam("q", "test")
                                        .request(String.class))
                                .thenAccept(System.out::println)
                                .exceptionally(throwable -> {
                                    // handle client error
                                    LOGGER.log(Level.SEVERE, "Failed to invoke client", throwable);
                                    return null;
                                })
                                // this is to make sure the VM does not exit before finishing the call
                                .toCompletableFuture()
                                .get();

        //        client.get()
        //                .uri("https://www.google.com/search")
        //                .queryParam("q", "ahoj")
        //                .request()
        //                .thenCompose(it -> {
        //                    CompletableFuture<String> result = new CompletableFuture<>();
        //                    it.content().subscribe(new Flow.Subscriber<DataChunk>() {
        //                        private Flow.Subscription subscription;
        //
        //                        @Override
        //                        public void onSubscribe(Flow.Subscription subscription) {
        //                            this.subscription = subscription;
        //
        //                            subscription.request(1);
        //                        }
        //
        //                        @Override
        //                        public void onNext(DataChunk item) {
        //                            System.out.println(new String(item.bytes()));
        //                            subscription.request(1);
        //                        }
        //
        //                        @Override
        //                        public void onError(Throwable throwable) {
        //                            throwable.printStackTrace();
        //                            result.completeExceptionally(throwable);
        //                        }
        //
        //                        @Override
        //                        public void onComplete() {
        //                            System.out.println("Completed");
        //                            result.complete("Hotot");
        //                        }
        //                    });
        //
        //                    return result;
        //                })
        //                .exceptionally(throwable -> {
        //                    // handle client error
        //                    LOGGER.log(Level.SEVERE, "Failed to invoke client", throwable);
        //                    return null;
        //                })
        //                // this is to make sure the VM does not exit before finishing the call
        //                .toCompletableFuture()
        //                .get();

//        JsonObject json = Json.createObjectBuilder()
//                .add("greeting", "Hi small")
//                .build();
//        client.put()
//                .uri("http://localhost:8080/greet/greeting")
//                //.headers(clientRequestHeaders -> clientRequestHeaders.ifNoneMatch("asdasd"))
//                .submit(json)
//                .thenAccept(clientResponse -> System.out.println(clientResponse.status()))
//                .thenCompose(nothing -> client.get()
//                        .uri("http://localhost:8080/greet")
//                        .request(JsonObject.class)
//                        .thenAccept(System.out::println))
//                .exceptionally(throwable -> {
//                    // handle client error
//                    LOGGER.log(Level.SEVERE, "Failed to invoke client", throwable);
//                    return null;
//                })
//                .toCompletableFuture()
//                .get();
//        System.out.println(clientResponse.status());

        //        client.get()
        //                .uri("http://localhost:8080/greet")
        //                //                        .uri("https://www.google.com")
        //                .request(JsonObject.class)
        //                .thenAccept(System.out::println)
        //                //                .thenCompose(nothing -> client.get()
        //                //                        .uri("https://www.google.com/search")
        //                //                        .queryParam("q", "ahoj")
        //                //                        .request(String.class))
        //                //                .thenAccept(System.out::println)
        //                .exceptionally(throwable -> {
        //                    // handle client error
        //                    LOGGER.log(Level.SEVERE, "Failed to invoke client", throwable);
        //                    return null;
        //                })
        //                // this is to make sure the VM does not exit before finishing the call
        //                .toCompletableFuture()
        //                .get();
        //                client.get()
        //                        .uri("https://www.google.com/search")
        //                        .queryParam("q", "ahoj")
        //                        .request()
        //                        .thenApply(ClientResponse::content)
        //                        .thenCompose(FileSubscriber.create(Paths.get("D:\\test.txt"))::subscribeTo)
        //                        .thenAccept(path -> System.out.println("Download completed: " + path))
        //                        .exceptionally(throwable -> {
        //                            // handle client error
        //                            LOGGER.log(Level.SEVERE, "Failed to invoke client", throwable);
        //                            return null;
        //                        })
        //                        // this is to make sure the VM does not exit before finishing the call
        //                        .toCompletableFuture()
        //                        .get();
    }
}
