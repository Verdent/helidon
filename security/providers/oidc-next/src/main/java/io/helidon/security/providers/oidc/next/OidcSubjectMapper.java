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

import io.helidon.json.JsonObject;
import io.helidon.security.Grant;
import io.helidon.security.Principal;
import io.helidon.security.Role;
import io.helidon.security.Subject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.JwtUtil;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.providers.common.TokenCredential;

final class OidcSubjectMapper {
    private final String tenantId;
    private final OidcProviderProfile providerProfile;

    private OidcSubjectMapper(String tenantId, OidcProviderProfile providerProfile) {
        this.tenantId = tenantId;
        this.providerProfile = providerProfile;
    }

    static OidcSubjectMapper create(String tenantId, OidcProviderProfile providerProfile) {
        return new OidcSubjectMapper(tenantId, providerProfile);
    }

    String tenantId() {
        return tenantId;
    }

    OidcProviderProfile providerProfile() {
        return providerProfile;
    }

    Subject map(OidcValidatedJwt validatedToken) {
        Jwt jwt = validatedToken.jwt();
        SignedJwt signedJwt = validatedToken.signedJwt();
        String subject = jwt.subject().orElseThrow();
        Principal principal = principal(jwt, subject);

        TokenCredential.Builder credentialBuilder = TokenCredential.builder()
                .token(validatedToken.rawToken());
        jwt.issueTime().ifPresent(credentialBuilder::issueTime);
        jwt.expirationTime().ifPresent(credentialBuilder::expTime);
        jwt.issuer().ifPresent(credentialBuilder::issuer);
        credentialBuilder.addToken(Jwt.class, jwt);
        credentialBuilder.addToken(SignedJwt.class, signedJwt);

        Subject.Builder subjectBuilder = Subject.builder()
                .principal(principal)
                .addPublicCredential(TokenCredential.class, credentialBuilder.build());

        jwt.userGroups()
                .ifPresent(groups -> groups.forEach(group -> subjectBuilder.addGrant(Role.create(group))));
        jwt.scopes()
                .ifPresent(scopes -> scopes.forEach(scope -> subjectBuilder.addGrant(Grant.builder()
                                                                                 .name(scope)
                                                                                 .type("scope")
                                                                                 .build())));
        return subjectBuilder.build();
    }

    Subject map(OidcValidatedIntrospection validatedToken) {
        String principalId = validatedToken.principalId().orElseThrow();
        Principal.Builder principalBuilder = Principal.builder()
                .name(validatedToken.principalName().orElse(principalId))
                .id(principalId);

        validatedToken.claims()
                .keysAsStrings()
                .forEach(key -> validatedToken.claims()
                        .value(key)
                        .ifPresent(value -> principalBuilder.addAttribute(key, JwtUtil.toObject(value))));

        TokenCredential.Builder credentialBuilder = TokenCredential.builder()
                .token(validatedToken.rawToken());
        validatedToken.issueTime().ifPresent(credentialBuilder::issueTime);
        validatedToken.expirationTime().ifPresent(credentialBuilder::expTime);
        validatedToken.issuer().ifPresent(credentialBuilder::issuer);
        credentialBuilder.addToken(JsonObject.class, validatedToken.claims());

        Subject.Builder subjectBuilder = Subject.builder()
                .principal(principalBuilder.build())
                .addPublicCredential(TokenCredential.class, credentialBuilder.build());

        validatedToken.groups()
                .forEach(group -> subjectBuilder.addGrant(Role.create(group)));
        validatedToken.scopes()
                .forEach(scope -> subjectBuilder.addGrant(Grant.builder()
                                                        .name(scope)
                                                        .type("scope")
                                                        .build()));
        return subjectBuilder.build();
    }

    private Principal principal(Jwt jwt, String subject) {
        String name = jwt.preferredUsername()
                .orElse(subject);
        Principal.Builder builder = Principal.builder()
                .name(name)
                .id(subject);

        jwt.payloadClaimsJson()
                .forEach((key, jsonValue) -> builder.addAttribute(key, JwtUtil.toObject(jsonValue)));
        jwt.email().ifPresent(value -> builder.addAttribute("email", value));
        jwt.emailVerified().ifPresent(value -> builder.addAttribute("email_verified", value));
        jwt.locale().ifPresent(value -> builder.addAttribute("locale", value));
        jwt.familyName().ifPresent(value -> builder.addAttribute("family_name", value));
        jwt.givenName().ifPresent(value -> builder.addAttribute("given_name", value));
        jwt.fullName().ifPresent(value -> builder.addAttribute("full_name", value));
        return builder.build();
    }
}
