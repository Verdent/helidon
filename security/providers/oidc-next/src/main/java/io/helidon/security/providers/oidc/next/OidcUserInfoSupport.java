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

import java.util.Optional;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonValueType;

final class OidcUserInfoSupport {
    private OidcUserInfoSupport() {
    }

    static boolean enabled(OidcTenantConfig tenantConfig) {
        return tenantConfig.userInfo()
                .filter(OidcUserInfoConfig::enabled)
                .isPresent();
    }

    static Result userInfo(OidcTenantContext tenantContext, String accessToken, OidcValidatedIdToken idToken) {
        if (!enabled(tenantContext.tenantConfig())) {
            return Result.success(Optional.empty());
        }

        Optional<JsonObject> userInfo = tenantContext.endpointClient().userInfo(accessToken);
        if (userInfo.isEmpty()) {
            return Result.failure("UserInfo Endpoint request failed");
        }
        if (!subjectMatches(userInfo.orElseThrow(), idToken)) {
            return Result.failure("UserInfo response is invalid");
        }
        return Result.success(userInfo);
    }

    static boolean subjectMatches(JsonObject userInfo, OidcValidatedIdToken idToken) {
        /*
         * Spec: OpenID Connect Core 1.0, 5.3.2 Successful UserInfo Response
         * https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
         * Quotes: "`sub` Claim MUST always be returned";
         * "MUST be verified to exactly match the `sub` Claim in the ID Token".
         */
        String idTokenSubject = idToken.jwt()
                .subject()
                .orElseThrow();
        return subject(userInfo)
                .filter(idTokenSubject::equals)
                .isPresent();
    }

    private static Optional<String> subject(JsonObject userInfo) {
        return userInfo.value("sub")
                .filter(value -> value.type() == JsonValueType.STRING)
                .map(value -> value.asString().value())
                .filter(value -> !value.isBlank());
    }

    record Result(Optional<JsonObject> userInfo, String failureDescription) {
        private static Result success(Optional<JsonObject> userInfo) {
            return new Result(userInfo, null);
        }

        private static Result failure(String errorDescription) {
            return new Result(Optional.empty(), errorDescription);
        }

        boolean succeeded() {
            return failureDescription == null;
        }

        Optional<String> errorDescription() {
            return Optional.ofNullable(failureDescription);
        }
    }
}
