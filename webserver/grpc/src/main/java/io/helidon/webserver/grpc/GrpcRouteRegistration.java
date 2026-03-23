/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
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

package io.helidon.webserver.grpc;

import io.helidon.service.registry.Service;
import io.helidon.webserver.WebServer;

/**
 * A contract for generated gRPC route registrations.
 * <p>
 * Implementations are expected to be {@link io.helidon.service.registry.ServiceRegistry} services
 * and are consumed by the gRPC server feature during startup.
 */
@Service.Contract
public interface GrpcRouteRegistration {
    /**
     * Descriptor of the gRPC service to register.
     *
     * @return descriptor to expose on the server
     */
    GrpcServiceDescriptor descriptor();

    /**
     * Named socket this registration should be added to.
     *
     * @return socket name
     */
    default String socket() {
        return WebServer.DEFAULT_SOCKET_NAME;
    }

    /**
     * Whether the socket defined in {@link #socket()} must be present.
     *
     * @return {@code true} if the socket must exist, {@code false} otherwise
     */
    default boolean socketRequired() {
        return false;
    }
}
