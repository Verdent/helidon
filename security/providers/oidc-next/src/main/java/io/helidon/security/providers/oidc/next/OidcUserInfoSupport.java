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
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonValue;
import io.helidon.json.JsonValueType;

final class OidcUserInfoSupport {
    private OidcUserInfoSupport() {
    }

    static boolean enabled(OidcTenantConfig tenantConfig) {
        return tenantConfig.userInfo()
                .filter(OidcUserInfoConfig::enabled)
                .isPresent();
    }

    static Result userInfo(OidcTenantContext tenantContext,
                           String accessToken,
                           OidcValidatedIdToken idToken,
                           Instant validationTime) {
        Objects.requireNonNull(validationTime);
        if (!enabled(tenantContext.tenantConfig())) {
            return Result.success(Optional.empty());
        }

        OidcUserInfoEndpointResult endpointResult = tenantContext.endpointClient().userInfo(accessToken);
        if (!endpointResult.succeeded()) {
            return Result.failure("UserInfo Endpoint request failed", endpointResult.cause().orElse(null));
        }
        Optional<OidcUserInfoJwtProcessor> jwtProcessor = tenantContext.userInfoJwtProcessor();
        Optional<JsonObject> userInfo;
        if (endpointResult.json().isPresent()) {
            if (jwtProcessor.isPresent()) {
                return Result.failure("UserInfo response is invalid",
                                      "Registered JWT UserInfo response was returned as JSON",
                                      null);
            }
            userInfo = endpointResult.json();
        } else if (endpointResult.jwt().isPresent()) {
            if (jwtProcessor.isEmpty()) {
                return Result.failure("UserInfo response is invalid",
                                      "Unexpected JWT UserInfo response",
                                      null);
            }
            OidcValidationResult<JsonObject> validationResult = jwtProcessor.orElseThrow()
                    .validate(endpointResult.jwt().orElseThrow(), tenantContext, idToken, validationTime);
            if (!validationResult.succeeded()) {
                return Result.failure("UserInfo response is invalid",
                                      validationResult.errorDescription().orElse("UserInfo JWT validation failed"),
                                      validationResult.cause().orElse(null));
            }
            userInfo = validationResult.validatedToken();
        } else {
            return Result.failure("UserInfo response is invalid", "UserInfo response body is missing", null);
        }
        JsonObject userInfoClaims = userInfo.orElseThrow();
        if (!subjectMatches(userInfoClaims, idToken)) {
            return Result.failure("UserInfo response is invalid");
        }
        return Result.success(storedUserInfo(tenantContext.tenantConfig(), userInfoClaims));
    }

    static boolean subjectMatches(JsonObject userInfo, OidcValidatedIdToken idToken) {
        /*
         * Spec: OpenID Connect Core 1.0, 5.3.2 Successful UserInfo Response
         * https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
         * Quote: "The `sub` (subject) Claim MUST always be returned in the UserInfo Response."
         * Quote: "The `sub` Claim in the UserInfo Response MUST be verified to exactly match the `sub` Claim in the
         * ID Token."
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

    private static Optional<JsonObject> storedUserInfo(OidcTenantConfig tenantConfig, JsonObject userInfo) {
        OidcUserInfoConfig config = tenantConfig.userInfo()
                .orElseThrow();
        return switch (config.storagePolicy()) {
        case ALL -> Optional.of(userInfo);
        case MAPPED -> Optional.of(mappedUserInfo(userInfo, tenantConfig.subjectMapping(), config));
        case NONE -> Optional.empty();
        };
    }

    private static JsonObject mappedUserInfo(JsonObject userInfo,
                                             OidcSubjectMappingConfig subjectMapping,
                                             OidcUserInfoConfig config) {
        /*
         * Spec: OpenID Connect Core 1.0, 17.1 Personally Identifiable Information
         * https://openid.net/specs/openid-connect-core-1_0.html#PII
         * Quote: "Only necessary UserInfo data should be stored at the Client".
         */
        Set<String> claimPaths = new LinkedHashSet<>();
        claimPaths.add("sub");
        claimPaths.addAll(subjectMapping.principalIdClaimPaths());
        claimPaths.addAll(subjectMapping.principalNameClaimPaths());
        claimPaths.addAll(subjectMapping.roleClaimPaths());
        claimPaths.addAll(subjectMapping.scopeClaimPaths());
        claimPaths.addAll(config.attributeClaimPaths());

        JsonObject result = JsonObject.empty();
        for (String claimPath : claimPaths) {
            result = withClaimPath(userInfo, result, claimPath);
        }
        return result;
    }

    private static JsonObject withClaimPath(JsonObject source, JsonObject target, String claimPath) {
        String[] segments = claimPath.split("\\.");
        Optional<JsonValue> value = claimValue(source, segments);
        if (value.isEmpty()) {
            return target;
        }
        return withClaimPath(target, segments, 0, value.orElseThrow());
    }

    private static Optional<JsonValue> claimValue(JsonObject source, String[] segments) {
        JsonValue current = source.value(segments[0])
                .orElse(null);
        for (int i = 1; i < segments.length; i++) {
            if (current == null || current.type() != JsonValueType.OBJECT) {
                return Optional.empty();
            }
            current = current.asObject()
                    .value(segments[i])
                    .orElse(null);
        }
        return Optional.ofNullable(current);
    }

    private static JsonObject withClaimPath(JsonObject target, String[] segments, int index, JsonValue value) {
        JsonObject.Builder builder = JsonObject.builder()
                .from(target);
        String segment = segments[index];
        if (index == segments.length - 1) {
            builder.set(segment, value);
            return builder.build();
        }

        JsonObject nestedTarget = target.value(segment)
                .filter(existing -> existing.type() == JsonValueType.OBJECT)
                .map(JsonValue::asObject)
                .orElse(JsonObject.empty());
        builder.set(segment, withClaimPath(nestedTarget, segments, index + 1, value));
        return builder.build();
    }

    record Result(Optional<JsonObject> userInfo,
                  Optional<String> failureDescription,
                  Optional<String> diagnosticDescription,
                  Optional<Throwable> cause) {
        Result {
            userInfo = Objects.requireNonNull(userInfo);
            failureDescription = Objects.requireNonNull(failureDescription);
            diagnosticDescription = Objects.requireNonNull(diagnosticDescription);
            cause = Objects.requireNonNull(cause);
        }

        private static Result success(Optional<JsonObject> userInfo) {
            return new Result(userInfo, Optional.empty(), Optional.empty(), Optional.empty());
        }

        private static Result failure(String errorDescription) {
            return failure(errorDescription, null);
        }

        private static Result failure(String errorDescription, Throwable cause) {
            return failure(errorDescription, errorDescription, cause);
        }

        private static Result failure(String errorDescription, String diagnosticDescription, Throwable cause) {
            return new Result(Optional.empty(),
                              Optional.of(errorDescription),
                              Optional.of(diagnosticDescription),
                              Optional.ofNullable(cause));
        }

        boolean succeeded() {
            return failureDescription.isEmpty();
        }

        Optional<String> errorDescription() {
            return failureDescription;
        }
    }
}
