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

import java.util.Optional;
import java.util.function.Function;

import io.helidon.common.http.DataChunk;
import io.helidon.common.http.Reader;
import io.helidon.common.reactive.Flow;

/**
 * TODO javadoc.
 */
public interface ClientContentHandler<T> {
    /**
     * Reader to be used when receiving response from remote site.
     *
     * @return
     */
    Optional<Reader<T>> reader(ClientRequestBuilder.ClientRequest originalRequest, ClientResponse response);

    /**
     * Writer to be used when sending request to remote site.
     *
     * @return
     */
    Optional<Function<T, Flow.Publisher<DataChunk>>> writer(ClientRequestBuilder clientRequestBuilder);

    /**
     * Whether this content handler supports entities of the class specified.
     *
     * @param clazz class to check support
     * @return true if supported and should be used to process write/read of such an entity, false if not supported
     */
    boolean supports(Class<?> clazz);
}
