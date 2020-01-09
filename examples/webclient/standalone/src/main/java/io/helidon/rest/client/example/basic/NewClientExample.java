/*
 * Copyright (c) 2020 Oracle and/or its affiliates. All rights reserved.
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
import io.helidon.webclient.Proxy;
import io.helidon.webclient.Ssl;
import io.helidon.webclient.WebClient;

/**
 * A new web client example.
 */
public class NewClientExample {
    private static final Logger LOGGER = Logger.getLogger(NewClientExample.class.getName());

    public static void main(String[] args) throws ExecutionException, InterruptedException {
        Config config = Config.create();
        WebClient client = WebClient.builder()
                .config(config.get("client"))
                .build();

        client.get()
                .uri("https://www.google.com")
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
