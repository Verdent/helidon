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

import java.time.Duration;

import io.helidon.builder.api.Prototype;

final class OidcAuthorizationCodeConfigDecorator
        implements Prototype.BuilderDecorator<OidcAuthorizationCodeConfig.BuilderBase<?, ?>> {
    private static final Duration MIN_REFRESH_RESULT_RETENTION = Duration.ofSeconds(1);
    private static final Duration MAX_REFRESH_RESULT_RETENTION = Duration.ofMinutes(1);

    @Override
    public void decorate(OidcAuthorizationCodeConfig.BuilderBase<?, ?> target) {
        Duration retention = target.refreshResultRetention();
        if (retention.compareTo(MIN_REFRESH_RESULT_RETENTION) < 0) {
            throw new IllegalArgumentException("refresh-result-retention must be at least PT1S");
        }
        if (retention.compareTo(MAX_REFRESH_RESULT_RETENTION) > 0) {
            throw new IllegalArgumentException("refresh-result-retention must not exceed PT1M");
        }
        if (target.refreshResultCacheCapacity() < 1) {
            throw new IllegalArgumentException("refresh-result-cache-capacity must be positive");
        }
    }
}
