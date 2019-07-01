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

package io.helidon.microprofile.opentracing.tck;

import java.net.URI;
import java.util.LinkedList;
import java.util.List;

import io.helidon.common.CollectionsHelper;
import io.helidon.config.Config;
import io.helidon.tracing.Tag;
import io.helidon.tracing.TracerBuilder;

import io.opentracing.Tracer;
import io.opentracing.mock.MockTracer;

public final class OpentracingJavaMockTracerBuilder implements TracerBuilder<OpentracingJavaMockTracerBuilder> {

    static final String DEFAULT_PROTOCOL = "http";
    static final int DEFAULT_ZIPKIN_PORT = 9411;
    static final String DEFAULT_ZIPKIN_HOST = "127.0.0.1";
    static final boolean DEFAULT_ENABLED = true;

    private final List<Tag<?>> tags = new LinkedList<>();
    private String serviceName;
    private String protocol = DEFAULT_PROTOCOL;
    private String host = DEFAULT_ZIPKIN_HOST;
    private int port = DEFAULT_ZIPKIN_PORT;
    private String path;
    private String userInfo;
    private boolean enabled = DEFAULT_ENABLED;

    private OpentracingJavaMockTracerBuilder() {
    }

    /**
     * Get a Zipkin {@link Tracer} builder for processing tracing data of a service with a given name.
     *
     * @param serviceName name of the service that will be using the tracer.
     * @return {@code Tracer} builder for Zipkin.
     */
    public static OpentracingJavaMockTracerBuilder forService(String serviceName) {
        return create()
                .serviceName(serviceName);
    }

    /**
     * Create a new builder based on values in configuration.
     * This requires at least a key "service" in the provided config.
     *
     * @param config configuration to load this builder from
     * @return a new builder instance.
     * @see OpentracingJavaMockTracerBuilder#config(Config)
     */
    public static OpentracingJavaMockTracerBuilder create(Config config) {
        String serviceName = config.get("service")
                .asString()
                .orElseThrow(() -> new IllegalArgumentException("Configuration must at least contain the service key"));

        return OpentracingJavaMockTracerBuilder.forService(serviceName)
                .config(config);
    }

    static TracerBuilder<OpentracingJavaMockTracerBuilder> create() {
        return new OpentracingJavaMockTracerBuilder();
    }

    @Override
    public OpentracingJavaMockTracerBuilder serviceName(String name) {
        this.serviceName = name;
        return this;
    }

    @Override
    public OpentracingJavaMockTracerBuilder collectorUri(URI uri) {
        TracerBuilder.super.collectorUri(uri);

        if (null != uri.getUserInfo()) {
            this.userInfo = uri.getUserInfo();
        }

        return this;
    }

    @Override
    public OpentracingJavaMockTracerBuilder collectorProtocol(String protocol) {
        this.protocol = protocol;
        return this;
    }

    @Override
    public OpentracingJavaMockTracerBuilder collectorHost(String host) {
        this.host = host;
        return this;
    }

    @Override
    public OpentracingJavaMockTracerBuilder collectorPort(int port) {
        this.port = port;
        return this;
    }

    @Override
    public OpentracingJavaMockTracerBuilder collectorPath(String path) {
        this.path = path;
        return this;
    }

    @Override
    public OpentracingJavaMockTracerBuilder enabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    @Override
    public OpentracingJavaMockTracerBuilder registerGlobal(boolean global) {
        return this;
    }

    @Override
    public OpentracingJavaMockTracerBuilder addTracerTag(String key, String value) {
        this.tags.add(Tag.create(key, value));
        return this;
    }

    @Override
    public OpentracingJavaMockTracerBuilder addTracerTag(String key, Number value) {
        this.tags.add(Tag.create(key, value));
        return this;
    }

    @Override
    public OpentracingJavaMockTracerBuilder addTracerTag(String key, boolean value) {
        this.tags.add(Tag.create(key, value));
        return this;
    }

    @Override
    public OpentracingJavaMockTracerBuilder config(Config config) {
        config.get("service").asString().ifPresent(this::serviceName);
        config.get("protocol").asString().ifPresent(this::collectorProtocol);
        config.get("host").asString().ifPresent(this::collectorHost);
        config.get("port").asInt().ifPresent(this::collectorPort);
        config.get("path").asString().ifPresent(this::collectorPath);
        config.get("enabled").asBoolean().ifPresent(this::enabled);

        config.get("tags").detach()
                .asMap()
                .orElseGet(CollectionsHelper::mapOf)
                .forEach(this::addTracerTag);

        config.get("boolean-tags")
                .asNodeList()
                .ifPresent(nodes -> {
                    nodes.forEach(node -> {
                        this.addTracerTag(node.key().name(), node.asBoolean().get());
                    });
                });

        config.get("int-tags")
                .asNodeList()
                .ifPresent(nodes -> {
                    nodes.forEach(node -> {
                        this.addTracerTag(node.key().name(), node.asInt().get());
                    });
                });

        return this;
    }

    /**
     * Builds the {@link Tracer} for Zipkin based on the configured parameters.
     *
     * @return the tracer
     */
    @Override
    public Tracer build() {
        return new MockTracer();
    }


}
