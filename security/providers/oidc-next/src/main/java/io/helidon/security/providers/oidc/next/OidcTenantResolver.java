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

package io.helidon.security.providers.oidc.next;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import io.helidon.security.ProviderRequest;
import io.helidon.security.SecurityEnvironment;

final class OidcTenantResolver {
    private static final String HOST = "Host";
    private static final String TENANT_VARIABLE = "{tenant}";

    private final OidcProviderConfig config;
    private final OidcTenantResolutionConfig tenantResolution;

    private OidcTenantResolver(OidcProviderConfig config) {
        this.config = config;
        this.tenantResolution = config.tenantResolution();
    }

    static OidcTenantResolver create(OidcProviderConfig config) {
        return new OidcTenantResolver(config);
    }

    Optional<String> tenantId(ProviderRequest request) {
        if (request != null) {
            SecurityEnvironment environment = request.env();
            Optional<String> tenantId = headerTenantId(environment)
                    .or(() -> pathTenantId(environment))
                    .or(() -> hostTenantId(environment));
            if (tenantId.isPresent()) {
                return tenantId;
            }
        }
        return defaultTenantId();
    }

    private Optional<String> headerTenantId(SecurityEnvironment environment) {
        return tenantResolution.headerName()
                .flatMap(header -> firstHeaderValue(environment, header));
    }

    private Optional<String> pathTenantId(SecurityEnvironment environment) {
        return tenantResolution.pathSegment()
                .flatMap(segment -> {
                    if (segment < 0) {
                        return Optional.empty();
                    }
                    return environment.path()
                            .flatMap(path -> {
                                List<String> segments = pathSegments(path);
                                if (segment >= segments.size()) {
                                    return Optional.empty();
                                }
                                return nonBlank(segments.get(segment));
                            });
                });
    }

    private Optional<String> hostTenantId(SecurityEnvironment environment) {
        return tenantResolution.hostTemplate()
                .flatMap(template -> host(environment)
                        .flatMap(host -> tenantFromHostTemplate(host, template)));
    }

    private Optional<String> defaultTenantId() {
        if (config.tenants().isEmpty()) {
            return Optional.empty();
        }
        Optional<String> defaultTenant = config.defaultTenant();
        if (defaultTenant.isPresent()) {
            return defaultTenant;
        }
        if (config.tenants().size() == 1) {
            return Optional.of(config.tenants().keySet().iterator().next());
        }
        return Optional.empty();
    }

    private static Optional<String> firstHeaderValue(SecurityEnvironment environment, String headerName) {
        List<String> values = environment.headers().get(headerName);
        if (values == null) {
            return Optional.empty();
        }
        return values.stream()
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .findFirst();
    }

    private static List<String> pathSegments(String path) {
        return Arrays.stream(path.split("/"))
                .filter(segment -> !segment.isEmpty())
                .toList();
    }

    private static Optional<String> host(SecurityEnvironment environment) {
        URI targetUri = environment.targetUri();
        if (targetUri != null) {
            Optional<String> targetHost = nonBlank(targetUri.getHost());
            if (targetHost.isPresent()) {
                return targetHost;
            }
        }
        return firstHeaderValue(environment, HOST)
                .map(OidcTenantResolver::hostWithoutPort)
                .flatMap(OidcTenantResolver::nonBlank);
    }

    private static String hostWithoutPort(String host) {
        if (host.startsWith("[")) {
            int end = host.indexOf(']');
            if (end != -1) {
                return host.substring(1, end);
            }
        }
        int portIndex = host.indexOf(':');
        if (portIndex == -1) {
            return host;
        }
        return host.substring(0, portIndex);
    }

    private static Optional<String> tenantFromHostTemplate(String host, String template) {
        int variableIndex = template.indexOf(TENANT_VARIABLE);
        if (variableIndex == -1 || template.indexOf(TENANT_VARIABLE, variableIndex + TENANT_VARIABLE.length()) != -1) {
            return Optional.empty();
        }

        String prefix = template.substring(0, variableIndex);
        String suffix = template.substring(variableIndex + TENANT_VARIABLE.length());
        if (!host.startsWith(prefix) || !host.endsWith(suffix)) {
            return Optional.empty();
        }

        String tenantId = host.substring(prefix.length(), host.length() - suffix.length());
        return nonBlank(tenantId);
    }

    private static Optional<String> nonBlank(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(value);
    }
}
