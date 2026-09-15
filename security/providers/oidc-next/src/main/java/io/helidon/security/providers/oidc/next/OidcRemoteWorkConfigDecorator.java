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

import io.helidon.builder.api.Prototype;

final class OidcRemoteWorkConfigDecorator
        implements Prototype.BuilderDecorator<OidcRemoteWorkConfig.BuilderBase<?, ?>> {
    @Override
    public void decorate(OidcRemoteWorkConfig.BuilderBase<?, ?> target) {
        if (target.maxConcurrent() < 1) {
            throw new IllegalArgumentException("max-concurrent must be positive");
        }
        if (target.maxQueued() < 0) {
            throw new IllegalArgumentException("max-queued must not be negative");
        }
        if (target.admissionTimeout().isNegative()) {
            throw new IllegalArgumentException("admission-timeout must not be negative");
        }
    }
}
