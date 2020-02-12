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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import io.helidon.common.http.DataChunk;
import io.helidon.common.http.Http;
import io.helidon.common.http.MediaType;
import io.helidon.common.reactive.Flow;
import io.helidon.media.common.MediaSupport;
import io.helidon.media.common.MessageBodyReadableContent;
import io.helidon.media.common.MessageBodyReader;
import io.helidon.media.common.MessageBodyReaderContext;
import io.helidon.webserver.HashRequestHeaders;

/**
 * Immutable implementation of the {@link ClientResponse}.
 */
final class ClientResponseImpl implements ClientResponse {

    private final ClientResponseHeadersImpl headers;
    private final Flow.Publisher<DataChunk> publisher;
    private final Http.ResponseStatus status;
    private final Http.Version version;
    private final MediaSupport mediaSupport;

    private ClientResponseImpl(Builder builder) {
        headers = ClientResponseHeaders.create(builder.headers);
        publisher = builder.publisher;
        status = builder.status;
        version = builder.version;
        mediaSupport = builder.mediaSupport;
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

        MessageBodyReaderContext readerContext = MessageBodyReaderContext.create(mediaSupport,
                                                                                            null,
                                                                                            headers,
                                                                                            mediaType);
        return MessageBodyReadableContent.create(publisher, readerContext);
    }

    @Override
    public ClientResponseHeaders headers() {
        return headers;
    }

    /**
     * Builder for {@link ClientResponseImpl}.
     */
    static class Builder implements io.helidon.common.Builder<ClientResponseImpl> {

        private final Map<String, List<String>> headers = new HashMap<>();

        private MediaSupport mediaSupport;
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
        public Builder contentPublisher(Flow.Publisher<DataChunk> publisher) {
            this.publisher = publisher;
            return this;
        }

        /**
         *
         *
         * @param mediaSupport
         * @return
         */
        public Builder mediaSupport(MediaSupport mediaSupport) {
            this.mediaSupport = mediaSupport;
            return this;
        }

        /**
         * Sets response status code.
         *
         * @param status response status code
         */
        public Builder status(Http.ResponseStatus status) {
            this.status = status;
            return this;
        }

        /**
         * Http version of the response.
         *
         * @param version response http version
         */
        public Builder httpVersion(Http.Version version) {
            this.version = version;
            return this;
        }

        /**
         * Adds header to the response.
         *
         * @param name header name
         * @param values header value
         */
        public Builder addHeader(String name, List<String> values) {
            this.headers.put(name, values);
            return this;
        }
    }
}
