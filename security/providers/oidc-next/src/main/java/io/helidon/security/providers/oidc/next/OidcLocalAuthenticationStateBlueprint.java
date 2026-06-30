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

import java.time.Instant;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.json.JsonObject;

/**
 * Persisted local OIDC authentication state.
 */
@Prototype.Blueprint(isPublic = false)
interface OidcLocalAuthenticationStateBlueprint {
    /**
     * Tenant identifier that created the authentication state.
     *
     * @return tenant identifier
     */
    String tenantId();

    /**
     * Validated ID Token.
     *
     * @return validated ID Token
     */
    @Option.Confidential
    OidcValidatedIdToken idToken();

    /**
     * Access token.
     *
     * @return access token
     */
    @Option.Confidential
    String accessToken();

    /**
     * Access-token type.
     *
     * @return access-token type
     */
    String tokenType();

    /**
     * Refresh token, when issued.
     *
     * @return refresh token
     */
    @Option.Confidential
    Optional<String> refreshToken();

    /**
     * Granted OAuth scope.
     *
     * @return granted scope
     */
    Optional<String> scope();

    /**
     * Stored UserInfo claims.
     *
     * @return stored UserInfo claims
     */
    @Option.Confidential
    Optional<JsonObject> userInfo();

    /**
     * Time at which this local authentication state was created.
     *
     * @return creation time
     */
    Instant createdAt();

    /**
     * Time at which this local authentication state expires.
     *
     * @return expiration time
     */
    Instant expiresAt();

    /**
     * Access-token expiration time, when supplied by the Token Endpoint.
     *
     * @return access-token expiration time
     */
    Optional<Instant> accessTokenExpiresAt();
}
