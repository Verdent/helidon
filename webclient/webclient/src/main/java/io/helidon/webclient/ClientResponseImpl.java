/*
 * Copyright (c) 2019, 2020 Oracle and/or its affiliates. All rights reserved.
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
package io.helidon.webclient;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.helidon.common.http.DataChunk;
import io.helidon.common.http.Http;
import io.helidon.common.http.MediaType;
import io.helidon.common.reactive.Flow;
import io.helidon.media.common.MediaSupport;
import io.helidon.media.common.MessageBodyReadableContent;
import io.helidon.media.common.MessageBodyReaderContext;
import io.helidon.webserver.HashRequestHeaders;

/**
 * Immutable implementation of the {@link ClientResponse}.
 */
final class ClientResponseImpl implements ClientResponse {

    //TODO Je to ok pouzit HashRequestHeaders??? tohle je response a tamto je request
    //EDIT: ClientResponseHeaders tu!
    private final HashRequestHeaders headers;
    private final Flow.Publisher<DataChunk> publisher;
    private final Http.ResponseStatus status;
    private final Http.Version version;

    private ClientResponseImpl(Builder builder) {
        headers = new HashRequestHeaders(builder.headers);
        publisher = builder.publisher;
        status = builder.status;
        version = builder.version;
    }

    /**
     * Creates builder for {@link ClientResponseImpl}.
     *
     * @return builder
     */
    public static Builder builder() {
        return new Builder();
    }

    @Override
    public Http.ResponseStatus status() {
        return status;
    }

    @Override
    public Http.Version version() {
        return version;
    }

    @Override
    public MessageBodyReadableContent content() {
        Optional<MediaType> mediaType = headers.contentType();
        MediaSupport mediaSupport = MediaSupport.createWithDefaults();

        return MessageBodyReadableContent.create(publisher, MessageBodyReaderContext.create(mediaSupport,
                                                                                            null,
                                                                                            headers,
                                                                                            mediaType));
    }

    @Override
    public ClientResponseHeaders headers() {
        return ClientResponseHeaders.create(headers);
    }

    /**
     * Builder for {@link ClientResponseImpl}.
     */
    static class Builder implements io.helidon.common.Builder<ClientResponseImpl> {

        private final Map<String, List<String>> headers = new HashMap<>();

        private Flow.Publisher<DataChunk> publisher;
        private Http.ResponseStatus status = Http.Status.INTERNAL_SERVER_ERROR_500;
        private Http.Version version = Http.Version.V1_1;

        @Override
        public ClientResponseImpl build() {
            return new ClientResponseImpl(this);
        }

        /**
         * Sets content publisher to the response.
         *
         * @param publisher content publisher
         */
        public void contentPublisher(Flow.Publisher<DataChunk> publisher) {
            this.publisher = publisher;
        }

        /**
         * Sets response status code.
         *
         * @param status response status code
         */
        public void status(Http.ResponseStatus status) {
            this.status = status;
        }

        /**
         * Http version of the response.
         *
         * @param version response http version
         */
        public void httpVersion(Http.Version version) {
            this.version = version;
        }

        /**
         * Adds header to the response.
         *
         * @param name header name
         * @param values header value
         */
        public void addHeader(String name, List<String> values) {
            //HttpUtil.isTransferEncodingChunked(response)
            this.headers.put(name, values);
        }
    }
}
