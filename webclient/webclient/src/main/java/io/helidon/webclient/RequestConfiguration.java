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

import java.net.URI;

import io.helidon.common.GenericType;

/**
 * TODO javadoc.
 */
class RequestConfiguration extends ClientConfiguration {

    private final URI requestURI;
    private final GenericType<?> genericType;

    private RequestConfiguration(Builder builder) {
        super(builder);
        requestURI = builder.requestURI;
        genericType = builder.genericType;
    }

    URI requestURI() {
        return requestURI;
    }

    GenericType<?> genericType() {
        return genericType;
    }

    static Builder builder(URI requestURI) {
        return new Builder(requestURI);
    }

    static class Builder extends ClientConfiguration.Builder<Builder, RequestConfiguration> {

        public GenericType<?> genericType;
        private URI requestURI;

        public Builder(URI requestURI) {
            this.requestURI = requestURI;
        }

        @Override
        public RequestConfiguration build() {
            return new RequestConfiguration(this);
        }
    }
}
