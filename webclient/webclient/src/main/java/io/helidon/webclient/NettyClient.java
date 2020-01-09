/*
 * Copyright (c) 2018, 2020 Oracle and/or its affiliates. All rights reserved.
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

import java.time.Duration;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.common.Version;
import io.helidon.common.http.Http;
import io.helidon.config.Config;

import io.netty.channel.nio.NioEventLoopGroup;

/*
 * This class must be:
 *   - thread safe
 *   - graalVm native-image safe (e.g. you must be able to store this class statically)
 *       - what about the base URI? only would work with prod config
 */
final class NettyClient implements WebClient {
    private static final Config EMPTY_CONFIG = Config.empty();
    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofMinutes(1);
    private static final Duration DEFAULT_READ_TIMEOUT = Duration.ofMinutes(10);
    private static final boolean DEFAULT_FOLLOW_REDIRECTS = false;
    private static final LazyValue<String> DEFAULT_USER_AGENT = LazyValue
            .create(() -> "Helidon/" + Version.VERSION + " (java " + System.getProperty("java.runtime.version") + ")");
    private static final Proxy DEFAULT_PROXY = Proxy.noProxy();
    private static final Ssl DEFAULT_SSL = Ssl.builder().build();

    // shared by all client instances
    //EDIT: prozkoumat jak funguji event loop grupy v netty?
    //Jedna sdilena ci pro kazdeho clienta zvlast?
    static final LazyValue<NioEventLoopGroup> EVENT_GROUP = LazyValue.create();
    private static final AtomicBoolean DEFAULTS_CONFIGURED = new AtomicBoolean();

    private static final ClientConfiguration DEFAULT_CONFIGURATION =
            ClientConfiguration.builder()
                    .connectTimeout(DEFAULT_CONNECT_TIMEOUT)
                    .readTimeout(DEFAULT_READ_TIMEOUT)
                    .followRedirects(DEFAULT_FOLLOW_REDIRECTS)
                    .userAgent(DEFAULT_USER_AGENT)
                    .proxy(DEFAULT_PROXY)
                    .ssl(DEFAULT_SSL)
                    .build();

    // configurable per client instance
    static final AtomicReference<ClientConfiguration> SHARED_CONFIGURATION = new AtomicReference<>(DEFAULT_CONFIGURATION);

    // this instance configuration
    private final ClientConfiguration configuration;

    /**
     * Creates new instance.
     *
     * @param builder client builder
     */
    NettyClient(Builder builder) {
        this.configuration = builder.configuration();

        // we need to configure these - if user wants to override, they must
        // do it before first usage
        configureDefaults(EMPTY_CONFIG);
    }

    @Override
    public ClientRequestBuilder put() {
        return ClientRequestBuilderImpl.create(EVENT_GROUP, configuration, Http.Method.PUT);
    }

    @Override
    public ClientRequestBuilder get() {
        return ClientRequestBuilderImpl.create(EVENT_GROUP, configuration, Http.Method.GET);
    }

    @Override
    public ClientRequestBuilder method(String method) {
        return ClientRequestBuilderImpl.create(EVENT_GROUP, configuration, Http.RequestMethod.create(method));
    }

    static void configureDefaults(Config globalConfig) {
        if (DEFAULTS_CONFIGURED.compareAndSet(false, true)) {
            Config config = globalConfig.get("client");
            ClientConfiguration.Builder<?, ?> builder = DEFAULT_CONFIGURATION.derive();
            Config eventLoopConfig = config.get("event-loop");
            int numberOfThreads = eventLoopConfig.get("workers")
                    .asInt()
                    .orElse(1);
            String threadNamePrefix = eventLoopConfig.get("name-prefix")
                    .asString()
                    .orElse("helidon-client-");
            AtomicInteger threadCounter = new AtomicInteger();

            ThreadFactory threadFactory =
                    r -> {
                        Thread result = new Thread(r, threadNamePrefix + threadCounter.getAndIncrement());
                        // we should exit the VM if client event loop is the only thread(s) running
                        result.setDaemon(true);
                        return result;
                    };

            EVENT_GROUP.set(
                    () -> new NioEventLoopGroup(numberOfThreads, threadFactory));

            builder.config(config);

            SHARED_CONFIGURATION.set(builder.build());
        }
    }

}
