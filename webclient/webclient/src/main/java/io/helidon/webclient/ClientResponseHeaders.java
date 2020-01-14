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

import java.net.URI;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import io.helidon.common.http.Headers;
import io.helidon.common.http.MediaType;
import io.helidon.common.http.Parameters;
import io.helidon.common.http.SetCookie;

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
    static ClientResponseHeadersImpl create(Map<String, List<String>> headers) {
        return new ClientResponseHeadersImpl(headers);
    }

        List<SetCookie> setCookies();

        Optional<URI> location();

        Optional<ZonedDateTime> lastModified();
        // TODO add other response headers
        // dodelat gettery na vsechny co jsou caste

        Optional<MediaType> contentType();
}
