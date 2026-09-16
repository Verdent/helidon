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

import java.util.Objects;
import java.util.Optional;

import io.helidon.common.uri.UriHost;

final class OidcHostTemplate {
    static final String TENANT_VARIABLE = "{tenant}";

    private final String value;
    private final String prefix;
    private final String suffix;

    private OidcHostTemplate(String value, String prefix, String suffix) {
        this.value = value;
        this.prefix = prefix;
        this.suffix = suffix;
    }

    static OidcHostTemplate create(String template) {
        Objects.requireNonNull(template);
        int variableIndex = template.indexOf(TENANT_VARIABLE);
        if (variableIndex == -1
                || template.indexOf(TENANT_VARIABLE, variableIndex + TENANT_VARIABLE.length()) != -1) {
            throw new IllegalArgumentException(
                    "tenant-resolution.host-template must contain exactly one {tenant} placeholder");
        }

        String templateWithoutTerminalDot = template.endsWith(".")
                ? template.substring(0, template.length() - 1)
                : template;
        String[] labels = templateWithoutTerminalDot.split("\\.", -1);
        int tenantLabelIndex = -1;
        for (int i = 0; i < labels.length; i++) {
            if (TENANT_VARIABLE.equals(labels[i])) {
                tenantLabelIndex = i;
                break;
            }
        }
        if (tenantLabelIndex == -1) {
            throw new IllegalArgumentException(
                    "tenant-resolution.host-template must contain {tenant} as a complete DNS label");
        }

        labels[tenantLabelIndex] = "x";
        String[] normalizedLabels;
        try {
            UriHost host = UriHost.create(String.join(".", labels));
            if (host.kind() != UriHost.Kind.DNS) {
                throw new IllegalArgumentException("Host template must describe a DNS name");
            }
            normalizedLabels = host.value().split("\\.", -1);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "tenant-resolution.host-template must be a valid DNS host template", e);
        }
        if (normalizedLabels.length != labels.length) {
            throw new IllegalArgumentException(
                    "tenant-resolution.host-template must use dots as DNS label separators");
        }
        normalizedLabels[tenantLabelIndex] = TENANT_VARIABLE;
        String value = String.join(".", normalizedLabels);
        int normalizedVariableIndex = value.indexOf(TENANT_VARIABLE);
        return new OidcHostTemplate(value,
                                    value.substring(0, normalizedVariableIndex),
                                    value.substring(normalizedVariableIndex + TENANT_VARIABLE.length()));
    }

    String value() {
        return value;
    }

    Optional<String> tenantId(UriHost host) {
        if (host.kind() != UriHost.Kind.DNS) {
            return Optional.empty();
        }
        String normalizedHost = host.value();
        if (!normalizedHost.startsWith(prefix) || !normalizedHost.endsWith(suffix)) {
            return Optional.empty();
        }
        int tenantEnd = normalizedHost.length() - suffix.length();
        if (tenantEnd <= prefix.length()) {
            return Optional.empty();
        }
        String tenantId = normalizedHost.substring(prefix.length(), tenantEnd);
        return tenantId.indexOf('.') == -1 ? Optional.of(tenantId) : Optional.empty();
    }
}
