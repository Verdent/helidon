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

import java.util.List;
import java.util.Optional;

import io.helidon.builder.api.Description;
import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

/**
 * OIDC endpoint authentication policy configuration.
 */
@Prototype.Blueprint(decorator = OidcEndpointPolicyConfigDecorator.class)
@Prototype.Configured
interface OidcEndpointPolicyConfigBlueprint {
    /**
     * Accepted credential types for requests handled by this endpoint.
     * <p>
     * When omitted, the provider infers accepted credentials from the tenant configuration: Protected Resource enables
     * {@link OidcEndpointCredential#BEARER_TOKEN}, and Authorization Code Flow enables
     * {@link OidcEndpointCredential#AUTHENTICATION_COOKIE}.
     *
     * @return accepted credential types
     */
    @Description("Accepted credential types for requests handled by this endpoint. When omitted, the provider infers "
            + "accepted credentials from the tenant configuration.")
    @Option.Configured
    @Option.Singular("acceptedCredential")
    List<OidcEndpointCredential> acceptedCredentials();

    /**
     * Response returned when no accepted credential authenticates the request.
     * <p>
     * When omitted, the provider uses {@link OidcAuthenticationFailureResponse#AUTHORIZATION_CODE_REDIRECT} for
     * authentication-cookie-only endpoints and {@link OidcAuthenticationFailureResponse#UNAUTHORIZED} otherwise.
     *
     * @return authentication failure response
     */
    @Description("Response returned when no accepted credential authenticates the request. When omitted, "
            + "authentication-cookie-only endpoints redirect and all other endpoint policies return 401.")
    @Option.Configured
    Optional<OidcAuthenticationFailureResponse> authenticationFailureResponse();
}
