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
import java.util.Locale;

import io.helidon.builder.api.Prototype;

final class OidcJwtAccessTokenConfigDecorator implements Prototype.BuilderDecorator<OidcJwtAccessTokenConfig.BuilderBase<?, ?>> {
    static final List<String> RFC_9068_TYPES = List.of("at+jwt", "application/at+jwt");

    @Override
    public void decorate(OidcJwtAccessTokenConfig.BuilderBase<?, ?> target) {
        if (target.allowedTypes().isEmpty()) {
            throw new IllegalArgumentException("token-validation.jwt.allowed-types must not be empty");
        }
        boolean nonStandardType = false;
        for (String type : target.allowedTypes()) {
            if (type == null || type.isBlank() || !type.equals(type.strip())) {
                throw new IllegalArgumentException("token-validation.jwt.allowed-types must not contain blank or padded values");
            }
            nonStandardType |= !RFC_9068_TYPES.contains(type.toLowerCase(Locale.ROOT));
        }
        if (target.profile() == OidcJwtAccessTokenProfile.RFC_9068 && nonStandardType) {
            throw new IllegalArgumentException("token-validation.jwt.allowed-types must use RFC 9068 access-token types "
                                                      + "unless token-validation.jwt.profile is CUSTOM");
        }
        if (nonStandardType && target.requiredStringClaims().isEmpty()) {
            throw new IllegalArgumentException("token-validation.jwt.required-string-claims must identify access tokens "
                                                      + "when custom header types are allowed");
        }
        if (!target.typHeaderRequired()) {
            if (target.profile() != OidcJwtAccessTokenProfile.CUSTOM) {
                throw new IllegalArgumentException("token-validation.jwt.typ-header-required can be false only for "
                                                           + "token-validation.jwt.profile CUSTOM");
            }
            if (target.requiredStringClaims().isEmpty()) {
                throw new IllegalArgumentException("token-validation.jwt.required-string-claims must identify access "
                                                           + "tokens when the typ header may be absent");
            }
        }
        for (String claim : target.requiredClaims()) {
            if (claim == null || claim.isBlank() || !claim.equals(claim.strip())) {
                throw new IllegalArgumentException("token-validation.jwt.required-claims must not contain blank or padded names");
            }
        }
        target.requiredStringClaims().forEach((claim, value) -> {
            if (claim == null || claim.isBlank() || !claim.equals(claim.strip())
                    || value == null || value.isBlank() || !value.equals(value.strip())) {
                throw new IllegalArgumentException("token-validation.jwt.required-string-claims must not contain "
                                                          + "blank or padded names or values");
            }
        });
    }
}
