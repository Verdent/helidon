/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package io.helidon.tracing.rest.client;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import io.helidon.webclient.ClientServiceRequest;
import io.helidon.webclient.spi.ClientService;

/**
 * TODO javadoc.
 */
public class ClientTracing implements ClientService {
    public static final String PARENT_SPAN = "io.helidon.rest.client.tracing.parentSpan";
    public static final String SPAN_NAME = "io.helidon.rest.client.tracing.spanName";

    public static ClientTracing create() {
        return null;
    }

    @Override
    public CompletionStage<ClientServiceRequest> request(ClientServiceRequest request) {
        return CompletableFuture.completedFuture(request);
    }
}
