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

final class OidcJwkSetConfigDecorator implements Prototype.BuilderDecorator<OidcJwkSetConfig.BuilderBase<?, ?>> {
    @Override
    public void decorate(OidcJwkSetConfig.BuilderBase<?, ?> target) {
        if (target.maxQueued() < 0) {
            throw new IllegalArgumentException("jwk-set.max-queued must not be negative");
        }
        if (target.admissionTimeout().isNegative()) {
            throw new IllegalArgumentException("jwk-set.admission-timeout must not be negative");
        }
    }
}
