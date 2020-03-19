/*
 * Copyright (c) 2020 Oracle and/or its affiliates.
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
package io.helidon.webclient.example;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import javax.json.Json;
import javax.json.JsonBuilderFactory;
import javax.json.JsonObject;

import io.helidon.common.http.Http;
import io.helidon.config.Config;
import io.helidon.config.ConfigValue;
import io.helidon.media.common.MediaSupport;
import io.helidon.media.jsonp.common.JsonProcessing;
import io.helidon.metrics.RegistryFactory;
import io.helidon.webclient.FileSubscriber;
import io.helidon.webclient.WebClient;
import io.helidon.webclient.WebClientResponse;
import io.helidon.webclient.metrics.WebClientMetrics;
import io.helidon.webclient.spi.WebClientService;

import org.eclipse.microprofile.metrics.Counter;
import org.eclipse.microprofile.metrics.MetricRegistry;

/**
 * A simple WebClient usage class.
 *
 * Each of the methods demonstrates different usage of the WebClient.
 */
public class WebClientExample {

    private static final MetricRegistry METRIC_REGISTRY = RegistryFactory.getInstance()
            .getRegistry(MetricRegistry.Type.APPLICATION);
    private static final JsonProcessing JSON_PROCESSING = JsonProcessing.create();
    private static final JsonBuilderFactory JSON_BUILDER = Json.createBuilderFactory(Collections.emptyMap());
    private static final JsonObject JSON_NEW_GREETING;

    static {
        JSON_NEW_GREETING = JSON_BUILDER.createObjectBuilder()
                .add("greeting", "Hola")
                .build();
    }

    private static String url;

    private WebClientExample() {}

    /**
     * Executes WebClient examples.
     *
     * If no argument provided it will take server port from configuration server.port.
     *
     * User can override port from configuration by main method parameter with the specific port.
     *
     * @param args main method
     * @throws ExecutionException   execution exception
     * @throws InterruptedException interrupted exception
     * @throws IOException          io exception
     */
    public static void main(String[] args) throws ExecutionException, InterruptedException, IOException {
        Config config = Config.create();
        if (args.length == 0) {
            ConfigValue<Integer> port = config.get("server.port").asInt();
            if (!port.isPresent() || port.get() == -1) {
                throw new IllegalStateException("Unknown port! Please specify port as a main method parameter "
                                                        + "or directly to config server.port");
            }
            url = "http://localhost:" + port.get() + "/greet";
        } else {
            url = "http://localhost:" + Integer.parseInt(args[0]) + "/greet";
        }

        WebClient webClient = WebClient.builder()
                .baseUri(url)
                .config(config.get("client"))
                //Since JSON processing support is not present by default, we have to add it.
                .mediaSupport(MediaSupport.builder()
                                      .registerDefaults()
                                      .registerReader(JSON_PROCESSING.newReader())
                                      .registerWriter(JSON_PROCESSING.newWriter())
                                      .build())
                .build();

        performPutMethod(webClient);
        performGetMethod(webClient);
        followRedirects(webClient);
        getResponseAsAnJsonObject(webClient);
        saveResponseToFile(webClient);
        registerClientMetric(url);
    }

    static void performPutMethod(WebClient webClient) throws ExecutionException, InterruptedException {
        System.out.println("Put request execution.");
        webClient.put()
                .path("/greeting")
                .submit(JSON_NEW_GREETING)
                .thenAccept(webClientResponse -> System.out.println("PUT request successfully executed."))
                .toCompletableFuture()
                .get();
    }

    static String performGetMethod(WebClient webClient) throws ExecutionException, InterruptedException {
        System.out.println("Get request execution.");
        return webClient.get()
                .request(String.class)
                .thenCompose(string -> {
                    System.out.println("GET request successfully executed.");
                    System.out.println(string);
                    return CompletableFuture.completedFuture(string);
                })
                .toCompletableFuture()
                .get();
    }

    static void followRedirects(WebClient webClient) throws ExecutionException, InterruptedException {
        System.out.println("Following request redirection.");
        webClient.get()
                .path("/redirect")
                .request()
                .thenCompose(response -> {
                    if (response.status() != Http.Status.OK_200) {
                        throw new IllegalStateException("Follow redirection failed!");
                    }
                    return response.content().as(String.class);
                })
                .thenAccept(string -> {
                    System.out.println("Redirected request successfully followed.");
                    System.out.println(string);
                })
                .toCompletableFuture()
                .get();
    }

    static void getResponseAsAnJsonObject(WebClient webClient) throws ExecutionException, InterruptedException {
        //Support for JsonObject reading from response is not present by default.
        //In case of this example it was registered at creation time of the WebClient instance.
        System.out.println("Requesting from JsonObject.");
        webClient.get()
                .request(JsonObject.class)
                .thenAccept(jsonObject -> {
                    System.out.println("JsonObject successfully obtained.");
                    System.out.println(jsonObject);
                })
                .toCompletableFuture()
                .get();
    }

    static void saveResponseToFile(WebClient webClient) throws ExecutionException, InterruptedException, IOException {
        //We have to create file subscriber first. This subscriber will save the content of the response to the file.
        Path file = Paths.get("test.txt");
        Files.deleteIfExists(file);
        FileSubscriber fileSubscriber = FileSubscriber.create(file);

        //Then it is needed obtain unhandled response content and subscribe file subscriber to it.
        System.out.println("Downloading server response to the file: " + file);
        webClient.get()
                .request()
                .thenApply(WebClientResponse::content)
                .thenCompose(fileSubscriber::subscribeTo)
                .thenAccept(path -> System.out.println("Download complete!"))
                .toCompletableFuture()
                .get();
    }

    static void registerClientMetric(String url) throws ExecutionException, InterruptedException {
        //This part here is only for verification purposes, it is not needed to be done for actual usage.
        String counterName = "example.metric.GET.localhost";
        Counter counter = METRIC_REGISTRY.counter(counterName);
        System.out.println(counterName + ": " + counter.getCount());

        //Creates new metric which will count all GET requests and has format of example.metric.GET.<host-name>
        WebClientService clientService = WebClientMetrics.counter()
                .methods(Http.Method.GET)
                .nameFormat("example.metric.%1$s.%2$s")
                .build();

        //This newly created metric now needs to be registered to WebClient.
        Config config = Config.create();
        WebClient webClient = WebClient.builder()
                .baseUri(url)
                .config(config)
                .register(clientService)
                .build();

        //Perform any GET request using this newly created WebClient instance.
        performGetMethod(webClient);

        //Verification for example purposes that metric has been incremented.
        System.out.println(counterName + ": " + counter.getCount());
    }
}
