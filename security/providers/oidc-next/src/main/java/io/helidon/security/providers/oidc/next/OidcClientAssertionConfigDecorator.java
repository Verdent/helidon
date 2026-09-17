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
import io.helidon.common.configurable.Resource;

final class OidcClientAssertionConfigDecorator
        implements Prototype.BuilderDecorator<OidcClientAssertionConfig.BuilderBase<?, ?>> {
    @Override
    public void decorate(OidcClientAssertionConfig.BuilderBase<?, ?> target) {
        // Buffer before runtime consumers share the configuration. bytes() also rejects an already-consumed source.
        target.jwk().ifPresent(Resource::bytes);
    }
}
