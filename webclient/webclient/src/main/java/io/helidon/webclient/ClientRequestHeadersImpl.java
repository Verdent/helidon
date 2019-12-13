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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import io.helidon.common.http.Http;
import io.helidon.common.http.MediaType;
import io.helidon.common.http.Parameters;

import io.netty.handler.codec.http.cookie.ClientCookieEncoder;
import io.netty.handler.codec.http.cookie.DefaultCookie;

/**
 * TODO Javadoc
 */
class ClientRequestHeadersImpl implements ClientRequestHeaders {

    private final Map<String, List<String>> headers = new HashMap<>();

    ClientRequestHeadersImpl() {
    }

    ClientRequestHeadersImpl(ClientRequestHeaders headers) {
        this.headers.putAll(headers.toMap());
    }

    @Override
    public void unsetHeader(String name) {
        headers.remove(name);
    }

    @Override
    public void addCookie(String name, String value) {
        add(Http.Header.COOKIE, ClientCookieEncoder.STRICT.encode(new DefaultCookie(name, value)));
    }

    @Override
    public void contentType(MediaType contentType) {
        put(Http.Header.CONTENT_TYPE, contentType.toString());
    }

    @Override
    public void contentLength(long length) {
        put(Http.Header.CONTENT_LENGTH, Long.toString(length));
    }

    @Override
    public void addAccept(MediaType mediaType) {
        add(Http.Header.ACCEPT, mediaType.toString());
    }

    @Override
    public List<MediaType> acceptedTypes() {
        List<MediaType> mediaTypes = new ArrayList<>();
        headers.computeIfAbsent(Http.Header.ACCEPT, k -> new ArrayList<>())
                .forEach(s -> mediaTypes.add(MediaType.parse(s)));
        return Collections.unmodifiableList(mediaTypes);
    }

    @Override
    public Optional<MediaType> mediaType() {
        List<String> contentType = headers.computeIfAbsent(Http.Header.CONTENT_TYPE, k -> new ArrayList<>());
        return Optional.ofNullable(contentType.size() == 0 ? MediaType.WILDCARD : MediaType.parse(contentType.get(0)));
    }

    @Override
    public Optional<String> first(String name) {
        return Optional.ofNullable(headers.get(name)).map(list -> list.get(0));
    }

    @Override
    public List<String> all(String headerName) {
        return Collections.unmodifiableList(headers.getOrDefault(headerName, new ArrayList<>()));
    }

    @Override
    public List<String> put(String key, String... values) {
        List<String> list = headers.put(key, Arrays.asList(values));
        return Collections.unmodifiableList(list == null ? new ArrayList<>() : list);
    }

    @Override
    public List<String> put(String key, Iterable<String> values) {
        List<String> list = headers.put(key, iterableToList(values));
        return Collections.unmodifiableList(list == null ? new ArrayList<>() : list);
    }

    @Override
    public List<String> putIfAbsent(String key, String... values) {
        List<String> list = headers.putIfAbsent(key, Arrays.asList(values));
        return Collections.unmodifiableList(list == null ? new ArrayList<>() : list);
    }

    @Override
    public List<String> putIfAbsent(String key, Iterable<String> values) {
        List<String> list = headers.putIfAbsent(key, iterableToList(values));
        return Collections.unmodifiableList(list == null ? new ArrayList<>() : list);
    }

    @Override
    public List<String> computeIfAbsent(String key, Function<String, Iterable<String>> values) {
        List<String> associatedHeaders = headers.get(key);
        if (associatedHeaders == null) {
            return put(key, values.apply(key));
        }
        return Collections.unmodifiableList(associatedHeaders);
    }

    @Override
    public List<String> computeSingleIfAbsent(String key, Function<String, String> value) {
        List<String> associatedHeaders = headers.get(key);
        if (associatedHeaders == null) {
            return put(key, value.apply(key));
        }
        return Collections.unmodifiableList(associatedHeaders);
    }

    @Override
    public void putAll(Parameters parameters) {
        headers.putAll(parameters.toMap());
    }

    @Override
    public void add(String key, String... values) {
        headers.computeIfAbsent(key, k -> new ArrayList<>()).addAll(Arrays.asList(values));
    }

    @Override
    public void add(String key, Iterable<String> values) {
        headers.computeIfAbsent(key, k -> new ArrayList<>()).addAll(iterableToList(values));
    }

    @Override
    public void addAll(Parameters parameters) {
        parameters.toMap().forEach(this::add);
    }

    @Override
    public List<String> remove(String key) {
        List<String> value = headers.remove(key);
        return value == null ? new ArrayList<>() : value;
    }

    @Override
    public Map<String, List<String>> toMap() {
        return Collections.unmodifiableMap(new HashMap<>(headers));
    }

    private List<String> iterableToList(Iterable<String> iterable) {
        return StreamSupport
                .stream(iterable.spliterator(), false)
                .collect(Collectors.toList());
    }
}
