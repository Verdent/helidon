/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
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
package io.helidon.media.json.processing.client;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import javax.json.JsonStructure;

import io.helidon.common.http.DataChunk;
import io.helidon.common.http.MediaType;
import io.helidon.common.http.Reader;
import io.helidon.common.reactive.Flow;
import io.helidon.media.jsonp.common.JsonProcessing;
import io.helidon.webclient.ClientContentHandler;
import io.helidon.webclient.ClientRequestBuilder;
import io.helidon.webclient.ClientResponse;

/**
 * Support for JSON-P in Helidon WebClient.
 */
public final class ClientJsonpSupport implements ClientContentHandler<JsonStructure> {
    private final JsonProcessing jsonProcessing;
    private final Charset charset;

    private ClientJsonpSupport(Builder builder) {
        this.jsonProcessing = builder.processing;
        this.charset = builder.charset;
    }

    public static ClientJsonpSupport create() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public ClientJsonpSupport derive(Charset charset) {
        return ClientJsonpSupport.builder()
                .jsonProcessing(jsonProcessing)
                .charset(charset)
                .build();
    }

    public static class Builder implements io.helidon.common.Builder<ClientJsonpSupport> {
        private JsonProcessing processing;
        private Charset charset = StandardCharsets.UTF_8;

        private Builder() {
        }

        @Override
        public ClientJsonpSupport build() {
            if (null == processing) {
                processing = JsonProcessing.create();
            }
            return new ClientJsonpSupport(this);
        }

        public Builder jsonProcessing(JsonProcessing jsonProcessing) {
            this.processing = jsonProcessing;
            return this;
        }

        public Builder charset(Charset charset) {
            this.charset = charset;
            return this;
        }
    }

    @Override
    public Optional<Reader<JsonStructure>> reader(ClientRequestBuilder.ClientRequest originalRequest, ClientResponse response) {
        Optional<MediaType> maybeMediaType = response.headers().contentType();

        if (maybeMediaType.isPresent()) {
            MediaType mediaType = maybeMediaType.get();

            // this content type is supported
            if (supportedMedia(mediaType)) {
                // if content type is set and one of supported, return reader
                return Optional.of(mediaType.charset()
                                           .map(Charset::forName)
                                           .map(jsonProcessing::reader)
                                           .orElseGet(() -> jsonProcessing.reader(charset)));
            } else {
                // if content type is set on not supported, do not return reader
                return Optional.empty();
            }
        } else {
            // if content type is not set, check if it was accepted
            if (supportedMedia(originalRequest.headers().acceptedTypes())) {
                return Optional.of(jsonProcessing.reader());
            } else {
                return Optional.empty();
            }
        }
    }

    @Override
    public boolean supports(Class<?> type) {
        return JsonStructure.class.isAssignableFrom(type);
    }

    @Override
    public Optional<Function<JsonStructure, Flow.Publisher<DataChunk>>> writer(ClientRequestBuilder clientRequestBuilder) {
        updateAccept(clientRequestBuilder, charset);

        Optional<MediaType> maybeMediaType = clientRequestBuilder.headers().mediaType();

        if (maybeMediaType.isPresent()) {
            MediaType mediaType = maybeMediaType.get();
            if (supportedMedia(mediaType)) {
                // content type is set and supported - use charset from it or default
                return Optional.of(mediaType.charset()
                                           .map(Charset::forName)
                                           .map(jsonProcessing::writer)
                                           .orElseGet(jsonProcessing::writer));
            } else {
                // content type is set and not supported
                return Optional.empty();
            }
        } else {
            // if content type is not set, set it to application/json
            clientRequestBuilder.headers().contentType(MediaType.APPLICATION_JSON);
            return Optional.of(jsonProcessing.writer());
        }
    }

    private void updateAccept(ClientRequestBuilder clientRequestBuilder, Charset charset) {
        if (supportedMedia(clientRequestBuilder.headers().acceptedTypes())) {
            return;
        }

        if (null == charset) {
            clientRequestBuilder.headers().addAccept(MediaType.APPLICATION_JSON);
        } else {
            clientRequestBuilder.headers().addAccept(MediaType.APPLICATION_JSON.withCharset(charset.name()));
        }
    }

    private boolean supportedMedia(List<MediaType> acceptedTypes) {
        for (MediaType acceptedType : acceptedTypes) {
            if (supportedMedia(acceptedType)) {
                return true;
            }
        }

        return false;
    }

    private boolean supportedMedia(MediaType mediaType) {
        //return jsonProcessing.isSupported(mediaType);
        // TODO how should this be done?
        return true;
    }
}
