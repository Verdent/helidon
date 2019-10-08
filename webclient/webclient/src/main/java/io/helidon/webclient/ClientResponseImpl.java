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
package io.helidon.webclient;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import java.util.function.Predicate;

import io.helidon.common.http.Content;
import io.helidon.common.http.DataChunk;
import io.helidon.common.http.Http;
import io.helidon.common.http.Reader;
import io.helidon.common.reactive.Flow;

/**
 * TODO javadoc.
 */
final class ClientResponseImpl implements ClientResponse {
    private final Map<String, List<String>> headers;
    private final Flow.Publisher<DataChunk> publisher;
    private final Http.ResponseStatus status;
    private final Http.Version version;

    private ClientResponseImpl(Builder builder) {
        headers = new HashMap<>(builder.headers);
        publisher = builder.publisher;
        status = builder.status;
        version = builder.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public Http.ResponseStatus status() {
        return status;
    }

    @Override
    public Content content() {
        return new Content() {
            private volatile Flow.Publisher<DataChunk> currentPublisher = publisher;

            @Override
            public void subscribe(Flow.Subscriber<? super DataChunk> subscriber) {
                currentPublisher.subscribe(subscriber);
            }

            @Override
            public void registerFilter(Function<Flow.Publisher<DataChunk>, Flow.Publisher<DataChunk>> function) {
                currentPublisher = function.apply(currentPublisher);
            }

            @Override
            public <T> void registerReader(Class<T> type, Reader<T> reader) {
                // TODO implement
            }

            @Override
            public <T> void registerReader(Predicate<Class<?>> predicate, Reader<T> reader) {
                // TODO implement
            }

            @Override
            public <T> CompletionStage<T> as(Class<T> type) {
                // TODO implement
                // hardcode to string for now
                CompletableFuture<T> result = new CompletableFuture<>();

                currentPublisher.subscribe(new Flow.Subscriber<DataChunk>() {
                    private ByteArrayOutputStream stream = new ByteArrayOutputStream();

                    @Override
                    public void onSubscribe(Flow.Subscription subscription) {
                        // TODO this is a dirty hack to poc
                        subscription.request(Long.MAX_VALUE);
                    }

                    @Override
                    public void onNext(DataChunk item) {
                        try {
                            stream.write(item.bytes());
                        } catch (IOException ignored) {
                            // should be able to write to an in-memory stream
                        } finally {
                            item.release();
                        }
                    }

                    @Override
                    public void onError(Throwable throwable) {
                        result.completeExceptionally(throwable);
                        stream = null;
                    }

                    @SuppressWarnings("unchecked")
                    @Override
                    public void onComplete() {
                        result.complete((T) new String(stream.toByteArray(), StandardCharsets.UTF_8));
                        stream = null;
                    }
                });

                return result;
            }
        };
    }

    @Override
    public ClientResponseHeaders headers() {
        return ClientResponseHeaders.create(headers);
    }

    static class Builder implements io.helidon.common.Builder<ClientResponseImpl> {

        private final Map<String, List<String>> headers = new HashMap<>();

        private Flow.Publisher<DataChunk> publisher;
        private Http.ResponseStatus status = Http.Status.INTERNAL_SERVER_ERROR_500;
        private Http.Version version = Http.Version.V1_1;

        @Override
        public ClientResponseImpl build() {
            return new ClientResponseImpl(this);
        }

        public void contentPublisher(Flow.Publisher<DataChunk> publisher) {
            this.publisher = publisher;
        }

        public void status(Http.ResponseStatus status) {
            this.status = status;
        }

        public void httpVersion(Http.Version version) {
            this.version = version;
        }

        public void addHeader(String name, List<String> values) {
            //HttpUtil.isTransferEncodingChunked(response)
            this.headers.put(name, values);
        }
    }
}
