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
package io.helidon.security.rest.client;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletionStage;
import java.util.logging.Logger;

import io.helidon.common.CollectionsHelper;
import io.helidon.common.context.Context;
import io.helidon.security.EndpointConfig;
import io.helidon.security.OutboundSecurityClientBuilder;
import io.helidon.security.OutboundSecurityResponse;
import io.helidon.security.Security;
import io.helidon.security.SecurityContext;
import io.helidon.security.SecurityEnvironment;
import io.helidon.webclient.ClientRequestHeaders;
import io.helidon.webclient.ClientServiceRequest;
import io.helidon.webclient.spi.ClientService;

import io.opentracing.Span;
import io.opentracing.SpanContext;
import io.opentracing.Tracer;
import io.opentracing.tag.Tags;

/**
 * TODO javadoc.
 */
public class ClientSecurity implements ClientService {
    private static final Logger LOGGER = Logger.getLogger(ClientSecurity.class.getName());

    public static final String PROVIDER_NAME = "io.helidon.security.rest.client.security.providerName";

    private Security security;

    private ClientSecurity() {
    }

    public static ClientSecurity create() {
        return new ClientSecurity();
    }

    public static ClientSecurity create(Security security) {
        ClientSecurity clientSecurity = create();
        clientSecurity.security = security;
        return clientSecurity;
    }

    @Override
    public CompletionStage<ClientServiceRequest> request(ClientServiceRequest request) {
        Context requestContext = request.context();
        // context either from request or create a new one
        SecurityContext context = requestContext.get(SecurityContext.class).orElseGet(() -> createContext(request));

        Span span = context.tracer()
                .buildSpan("security:outbound")
                .asChildOf(context.tracingSpan())
                .start();

        String explicitProvider = request.properties().first(PROVIDER_NAME).orElse(null);

        OutboundSecurityClientBuilder clientBuilder;

        try {
            SecurityEnvironment.Builder outboundEnv = context.env().derive();
            outboundEnv.method(request.method().name())
                    .path(request.path().toString())
                    .targetUri(request.uri())
                    .headers(request.headers().toMap());

            EndpointConfig.Builder outboundEp = context.endpointConfig().derive();
            Map<String, List<String>> propMap = request.properties().toMap();

            for (String name : propMap.keySet()) {
                outboundEp.addAtribute(name, request.properties().first(name));
            }

            clientBuilder = context.outboundClientBuilder()
                    .outboundEnvironment(outboundEnv)
                    .outboundEndpointConfig(outboundEp)
                    .explicitProvider(explicitProvider);

        } catch (Exception e) {
            traceError(span, e, null);

            throw e;
        }

        return clientBuilder.submit()
                .thenApply(providerResponse -> processResponse(request, span, providerResponse));
    }

    private ClientServiceRequest processResponse(ClientServiceRequest request,
                                                 Span span,
                                                 OutboundSecurityResponse providerResponse) {
        try {
            switch (providerResponse.status()) {
            case FAILURE:
            case FAILURE_FINISH:
                traceError(span,
                           providerResponse.throwable().orElse(null),
                           providerResponse.description()
                                   .orElse(providerResponse.status().toString()));
                break;
            case ABSTAIN:
            case SUCCESS:
            case SUCCESS_FINISH:
            default:
                break;
            }
            //EDIT: HTTP basic authentikace example omrknout
            Map<String, List<String>> newHeaders = providerResponse.requestHeaders();

            LOGGER.finest(() -> "Client filter header(s). SIZE: " + newHeaders.size());

            ClientRequestHeaders clientHeaders = request.headers();
            for (Map.Entry<String, List<String>> entry : newHeaders.entrySet()) {
                LOGGER.finest(() -> "    + Header: " + entry.getKey() + ": " + entry.getValue());

                //replace existing
                clientHeaders.remove(entry.getKey());
                for (String value : entry.getValue()) {
                    clientHeaders.put(entry.getKey(), value);
                }
            }
            span.finish();
            return request;
        } catch (Exception e) {
            traceError(span, e, null);
            throw e;
        }
    }

    private SecurityContext createContext(ClientServiceRequest request) {
        return security.contextBuilder(UUID.randomUUID().toString())
                .endpointConfig(EndpointConfig.builder()
                                        .build())
                .env(SecurityEnvironment.builder()
                             .path(request.path().toString())
                             //TODO everything else
                             .build())
                .tracingTracer(request.context().get(Tracer.class).orElse(null))
                .tracingSpan(request.context().get(SpanContext.class).orElse(null))
                .build();
    }

    static void traceError(Span span, Throwable throwable, String description) {
        // failed
        if (null != throwable) {
            Tags.ERROR.set(span, true);
            span.log(CollectionsHelper.mapOf("event", "error",
                                             "error.object", throwable));
        } else {
            Tags.ERROR.set(span, true);
            span.log(CollectionsHelper.mapOf("event", "error",
                                             "message", description,
                                             "error.kind", "SecurityException"));
        }
        span.finish();
    }
}
