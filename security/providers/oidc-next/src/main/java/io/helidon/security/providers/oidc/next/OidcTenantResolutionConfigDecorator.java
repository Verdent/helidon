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

import java.util.Arrays;
import java.util.List;

import io.helidon.builder.api.Prototype;

final class OidcTenantResolutionConfigDecorator
        implements Prototype.BuilderDecorator<OidcTenantResolutionConfig.BuilderBase<?, ?>> {
    private static final String TENANT_VARIABLE = "{tenant}";

    @Override
    public void decorate(OidcTenantResolutionConfig.BuilderBase<?, ?> target) {
        target.headerName()
                .filter(headerName -> headerName.isBlank() || !headerName.equals(headerName.strip()))
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException("tenant-resolution.header-name must not be blank or padded");
                });
        target.pathSegment()
                .filter(pathSegment -> pathSegment < 0)
                .ifPresent(ignored -> {
                    throw new IllegalArgumentException("tenant-resolution.path-segment must not be negative");
                });
        target.pathTemplate().ifPresent(pathTemplate -> {
            if (pathTemplate.isBlank() || !pathTemplate.equals(pathTemplate.strip())) {
                throw new IllegalArgumentException("tenant-resolution.path-template must not be blank or padded");
            }
            validateSingleTenantVariable(pathTemplate, "tenant-resolution.path-template");
            if (!pathTemplateSegments(pathTemplate).contains(TENANT_VARIABLE)) {
                throw new IllegalArgumentException(
                        "tenant-resolution.path-template must contain {tenant} as a complete path segment");
            }
        });
        target.hostTemplate().ifPresent(hostTemplate -> {
            if (hostTemplate.isBlank() || !hostTemplate.equals(hostTemplate.strip())) {
                throw new IllegalArgumentException("tenant-resolution.host-template must not be blank or padded");
            }
            validateSingleTenantVariable(hostTemplate, "tenant-resolution.host-template");
        });
    }

    private static void validateSingleTenantVariable(String template, String configKey) {
        int variableIndex = template.indexOf(TENANT_VARIABLE);
        if (variableIndex == -1
                || template.indexOf(TENANT_VARIABLE, variableIndex + TENANT_VARIABLE.length()) != -1) {
            throw new IllegalArgumentException(configKey + " must contain exactly one {tenant} placeholder");
        }
    }

    private static List<String> pathTemplateSegments(String pathTemplate) {
        return Arrays.stream(pathTemplate.split("/"))
                .filter(segment -> !segment.isEmpty())
                .toList();
    }
}
