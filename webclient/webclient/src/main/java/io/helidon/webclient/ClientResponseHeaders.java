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
package io.helidon.webclient;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import io.helidon.common.http.Headers;
import io.helidon.common.http.Parameters;

/**
 * Headers that may be available on response from server.
 */
public interface ClientResponseHeaders extends Headers {

    /**
     * Creates {@link ClientResponseHeaders} instance which contains data from {@link Parameters} instance.
     *
     * @param parameters headers in parameters instance
     * @return response headers instance
     */
    static ClientResponseHeaders create(Parameters parameters) {
        return create(parameters.toMap());
    }

    /**
     * Creates {@link ClientResponseHeaders} instance which contains data from {@link Map}.
     *
     * @param headers response headers in map
     * @return response headers instance
     */
    static ClientResponseHeaders create(Map<String, List<String>> headers) {
        return new ClientResponseHeaders() {
            @Override
            public List<String> all(String headerName) {
                List<String> response = headers.get(headerName);

                if (null == response) {
                    return Collections.emptyList();
                }
                return response;
            }

            @Override
            public Optional<String> first(String name) {
                return all(name).stream().findFirst();
            }

            @Override
            public List<String> put(String key, String... values) {
                throw new UnsupportedOperationException("Response headers cannot be modified");
            }

            @Override
            public List<String> put(String key, Iterable<String> values) {
                throw new UnsupportedOperationException("Response headers cannot be modified");
            }

            @Override
            public List<String> putIfAbsent(String key, String... values) {
                throw new UnsupportedOperationException("Response headers cannot be modified");
            }

            @Override
            public List<String> putIfAbsent(String key, Iterable<String> values) {
                throw new UnsupportedOperationException("Response headers cannot be modified");
            }

            @Override
            public List<String> computeIfAbsent(String key, Function<String, Iterable<String>> values) {
                throw new UnsupportedOperationException("Response headers cannot be modified");
            }

            @Override
            public List<String> computeSingleIfAbsent(String key, Function<String, String> value) {
                throw new UnsupportedOperationException("Response headers cannot be modified");
            }

            @Override
            public void putAll(Parameters parameters) {
                throw new UnsupportedOperationException("Response headers cannot be modified");
            }

            @Override
            public void add(String key, String... values) {
                throw new UnsupportedOperationException("Response headers cannot be modified");
            }

            @Override
            public void add(String key, Iterable<String> values) {
                throw new UnsupportedOperationException("Response headers cannot be modified");
            }

            @Override
            public void addAll(Parameters parameters) {
                throw new UnsupportedOperationException("Response headers cannot be modified");
            }

            @Override
            public List<String> remove(String key) {
                throw new UnsupportedOperationException("Response headers cannot be modified");
            }

            @Override
            public Map<String, List<String>> toMap() {
                return new HashMap<>(headers);
            }
        };
    }
    //
    //    List<SetCookie> setCookies();
    //
    //    Optional<URI> location();
    //
    //    Optional<ZonedDateTime> lastModified();
    //    // TODO add other response headers
    //    // dodelat gettery na vsechny co jsou caste
    //
    //    Optional<MediaType> contentType();
}
