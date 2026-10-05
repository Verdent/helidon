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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import io.helidon.json.JsonObject;
import io.helidon.json.JsonValue;
import io.helidon.json.JsonValueType;
import io.helidon.security.Grant;
import io.helidon.security.Principal;
import io.helidon.security.Role;
import io.helidon.security.Subject;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.JwtUtil;
import io.helidon.security.jwt.SignedJwt;
import io.helidon.security.providers.common.TokenCredential;
import io.helidon.security.providers.oidc.next.spi.OidcTenantAdapter;

final class OidcSubjectMapper {
    private static final String ISSUER_SUBJECT_PRINCIPAL_ID_PREFIX = "oidc-sub:";
    private static final String ISSUER_CLAIM_PRINCIPAL_ID_PREFIX = "oidc-claim:";
    private static final String NAMESPACE_PRINCIPAL_ID_PREFIX = "oidc-namespace:";
    private static final String ADAPTER_PRINCIPAL_ID_PREFIX = "oidc-adapter:";
    private static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder()
            .withoutPadding();
    private static final Set<String> ID_TOKEN_CLAIMS_PRESERVED_WHEN_MERGING_USER_INFO = Set.of("iss",
                                                                                               "sub",
                                                                                               "aud",
                                                                                               "exp",
                                                                                               "nbf",
                                                                                               "iat",
                                                                                               "jti",
                                                                                               "azp",
                                                                                               "nonce",
                                                                                               "auth_time",
                                                                                               "acr",
                                                                                               "amr",
                                                                                               "at_hash",
                                                                                               "c_hash",
                                                                                               "sid");

    private OidcSubjectMapper() {
    }

    static Subject map(OidcValidatedAccessToken validatedToken, OidcTenantContext tenantContext) {
        return switch (validatedToken) {
        case OidcValidatedJwt validatedJwt -> mapJwt(validatedJwt, tenantContext);
        case OidcValidatedIntrospection validatedIntrospection -> mapIntrospection(validatedIntrospection,
                                                                                    tenantContext);
        };
    }

    static Subject map(OidcLocalAuthenticationResult authenticationResult, OidcTenantContext tenantContext) {
        OidcSubjectMappingConfig subjectMapping = tenantContext.subjectMapping();
        Jwt idToken = authenticationResult.idToken().jwt();
        PrincipalIdentity identity = adaptedIdentity(localIdentity(idToken), tenantContext).orElseThrow();
        Optional<JsonObject> userInfo = authenticationResult.userInfo();

        TokenCredential.Builder credentialBuilder = TokenCredential.builder()
                .token(authenticationResult.accessToken());
        idToken.issuer().ifPresent(credentialBuilder::issuer);
        authenticationResult.accessTokenExpiresAt().ifPresent(credentialBuilder::expTime);

        Subject.Builder subjectBuilder = Subject.builder()
                .addPublicCredential(TokenCredential.class, credentialBuilder.build());

        if (userInfo.isPresent()) {
            JsonObject userInfoClaims = userInfo.orElseThrow();
            JsonObject mergedClaims = mergeUserInfo(idToken, userInfoClaims);
            subjectBuilder.principal(principal(idToken, mergedClaims, userInfoClaims, identity, subjectMapping));
            addRoles(subjectBuilder, roleClaimValues(mergedClaims, subjectMapping));
        } else {
            subjectBuilder.principal(principal(idToken, identity, subjectMapping));
            addRoles(subjectBuilder, roleClaimValues(idToken.payloadClaimsJson(), subjectMapping));
        }
        if (subjectMapping.scopeGrantsEnabled()) {
            authenticationResult.scope()
                    .stream()
                    .flatMap(scope -> OidcScopeSupport.parseScopeString(scope, "local authentication scope").stream())
                    .distinct()
                    .forEach(scope -> addScope(subjectBuilder, scope));
        }
        return subjectBuilder.build();
    }

    static Optional<String> principalId(JsonObject claims, OidcTenantContext tenantContext) {
        return introspectionIdentity(claims, tenantContext).map(PrincipalIdentity::id);
    }

    static Optional<String> principalId(Jwt jwt, OidcSubjectMappingConfig subjectMapping) {
        return jwtIdentity(jwt, subjectMapping).map(PrincipalIdentity::id);
    }

    static Optional<String> localPrincipalId(Jwt idToken) {
        return localIdentity(idToken).map(PrincipalIdentity::id);
    }

    private static JsonObject mergeUserInfo(Jwt idToken, JsonObject userInfo) {
        JsonObject.Builder builder = JsonObject.builder()
                .from(JsonObject.create(idToken.payloadClaimsJson()));
        userInfo.keysAsStrings()
                .stream()
                .filter(key -> !ID_TOKEN_CLAIMS_PRESERVED_WHEN_MERGING_USER_INFO.contains(key))
                .forEach(key -> userInfo.value(key).ifPresent(value -> builder.set(key, value)));
        return builder.build();
    }

    private static Subject mapJwt(OidcValidatedJwt validatedToken, OidcTenantContext tenantContext) {
        OidcSubjectMappingConfig subjectMapping = tenantContext.subjectMapping();
        Jwt jwt = validatedToken.jwt();
        SignedJwt signedJwt = validatedToken.signedJwt();
        PrincipalIdentity identity = adaptedIdentity(jwtIdentity(jwt, subjectMapping), tenantContext).orElseThrow();
        Principal principal = principal(jwt, identity, subjectMapping);

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

        addRoles(subjectBuilder, roleClaimValues(jwt.payloadClaimsJson(), subjectMapping));
        if (subjectMapping.scopeGrantsEnabled()) {
            scopeClaimValues(jwt.payloadClaimsJson(), subjectMapping).forEach(scope -> addScope(subjectBuilder, scope));
        }
        return subjectBuilder.build();
    }

    private static Subject mapIntrospection(OidcValidatedIntrospection validatedToken,
                                            OidcTenantContext tenantContext) {
        OidcSubjectMappingConfig subjectMapping = tenantContext.subjectMapping();
        PrincipalIdentity identity = adaptedIdentity(introspectionIdentity(validatedToken.claims(), tenantContext),
                                                     tenantContext).orElseThrow();
        Principal.Builder principalBuilder = principalBuilder(validatedToken.claims(), identity, subjectMapping);

        TokenCredential.Builder credentialBuilder = TokenCredential.builder()
                .token(validatedToken.rawToken());
        validatedToken.issueTime().ifPresent(credentialBuilder::issueTime);
        validatedToken.expirationTime().ifPresent(credentialBuilder::expTime);
        validatedToken.issuer().ifPresent(credentialBuilder::issuer);
        credentialBuilder.addToken(JsonObject.class, validatedToken.claims());

        Subject.Builder subjectBuilder = Subject.builder()
                .principal(principalBuilder.build())
                .addPublicCredential(TokenCredential.class, credentialBuilder.build());

        addRoles(subjectBuilder, roleClaimValues(validatedToken.claims(), subjectMapping));
        if (subjectMapping.scopeGrantsEnabled()) {
            scopeClaimValues(validatedToken.claims(), subjectMapping).forEach(scope -> addScope(subjectBuilder, scope));
        }
        return subjectBuilder.build();
    }

    private static Principal principal(Jwt jwt, PrincipalIdentity identity, OidcSubjectMappingConfig subjectMapping) {
        Principal.Builder builder = principalBuilder(jwt, identity, subjectMapping);
        return builder.build();
    }

    private static Principal principal(Jwt jwt,
                                       JsonObject mergedClaims,
                                       JsonObject userInfo,
                                       PrincipalIdentity identity,
                                       OidcSubjectMappingConfig subjectMapping) {
        Principal.Builder builder = principalBuilder(jwt, identity, subjectMapping);
        firstClaimValue(mergedClaims, subjectMapping.principalNameClaimPaths()).ifPresent(builder::name);
        userInfo.keysAsStrings()
                .stream()
                .filter(key -> !ID_TOKEN_CLAIMS_PRESERVED_WHEN_MERGING_USER_INFO.contains(key))
                .forEach(key -> userInfo.value(key)
                        .ifPresent(value -> builder.addAttribute(key, JwtUtil.toObject(value))));
        return builder.build();
    }

    private static Principal.Builder principalBuilder(Jwt jwt,
                                                      PrincipalIdentity identity,
                                                      OidcSubjectMappingConfig subjectMapping) {
        String name = firstClaimValue(jwt.payloadClaimsJson(), subjectMapping.principalNameClaimPaths())
                .orElse(identity.value());
        Principal.Builder builder = Principal.builder()
                .name(name)
                .id(identity.id());

        jwt.payloadClaimsJson()
                .forEach((key, jsonValue) -> builder.addAttribute(key, JwtUtil.toObject(jsonValue)));
        jwt.email().ifPresent(value -> builder.addAttribute("email", value));
        jwt.emailVerified().ifPresent(value -> builder.addAttribute("email_verified", value));
        jwt.locale().ifPresent(value -> builder.addAttribute("locale", value));
        jwt.familyName().ifPresent(value -> builder.addAttribute("family_name", value));
        jwt.givenName().ifPresent(value -> builder.addAttribute("given_name", value));
        jwt.fullName().ifPresent(value -> builder.addAttribute("full_name", value));
        return builder;
    }

    private static Principal.Builder principalBuilder(JsonObject claims,
                                                      PrincipalIdentity identity,
                                                      OidcSubjectMappingConfig subjectMapping) {
        String name = firstClaimValue(claims, subjectMapping.principalNameClaimPaths())
                .orElse(identity.value());
        Principal.Builder builder = Principal.builder()
                .name(name)
                .id(identity.id());
        claims.keysAsStrings()
                .forEach(key -> claims.value(key)
                        .ifPresent(value -> builder.addAttribute(key, JwtUtil.toObject(value))));
        return builder;
    }

    private static Optional<PrincipalIdentity> jwtIdentity(Jwt jwt, OidcSubjectMappingConfig subjectMapping) {
        return jwt.issuer()
                .flatMap(issuer -> firstClaim(name -> Optional.ofNullable(jwt.payloadClaimsJson().get(name)),
                                              subjectMapping.principalIdClaimPaths())
                        .flatMap(claim -> qualifiedIdentity(issuer, claim, true)));
    }

    private static Optional<PrincipalIdentity> localIdentity(Jwt idToken) {
        /*
         * Spec: OpenID Connect Core 1.0, 5.7 Claim Stability and Uniqueness
         * https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability
         * Quote: "the only guaranteed unique identifier for a given End-User is the combination of the `iss` Claim and
         * the `sub` Claim."
         */
        return idToken.issuer()
                .flatMap(issuer -> idToken.subject()
                        .flatMap(subject -> qualifiedIdentity(issuer, new SelectedClaim("sub", subject), true)));
    }

    private static Optional<PrincipalIdentity> adaptedIdentity(Optional<PrincipalIdentity> identity,
                                                               OidcTenantContext tenantContext) {
        Optional<String> namespace = tenantContext.tenantConfig()
                .adapter()
                .flatMap(OidcTenantAdapter::principalIdentityNamespace);
        if (namespace.isEmpty()) {
            return identity;
        }
        return encodedIdentityComponent(namespace.orElseThrow())
                .flatMap(encoded -> identity.map(value -> new PrincipalIdentity(ADAPTER_PRINCIPAL_ID_PREFIX
                                                                                        + encoded + "." + value.id(),
                                                                                value.value())));
    }

    private static Optional<PrincipalIdentity> introspectionIdentity(JsonObject claims, OidcTenantContext tenantContext) {
        /*
         * RFC 7662, 2.2 makes both iss and sub optional. Identity qualification is a local mapping policy, not an
         * additional wire requirement. Bind the authority to the trusted tenant, including when the response omits iss.
         * The validator checks a returned iss against the configured/discovered issuer before mapping the response.
         */
        OidcSubjectMappingConfig subjectMapping = tenantContext.subjectMapping();
        Optional<String> issuer = tenantContext.tokenValidation().issuer().or(tenantContext.metadata()::issuer);
        return firstClaim(claims::value, subjectMapping.principalIdClaimPaths())
                .flatMap(claim -> issuer.isPresent()
                        ? qualifiedIdentity(issuer.orElseThrow(), claim, true)
                        : subjectMapping.principalIdNamespace()
                                .flatMap(namespace -> qualifiedIdentity(namespace, claim, false)));
    }

    private static Optional<PrincipalIdentity> qualifiedIdentity(String authority, SelectedClaim claim, boolean issuer) {
        boolean issuerSubject = issuer && "sub".equals(claim.path());
        Optional<String> encodedAuthority = encodedIdentityComponent(authority);
        Optional<String> encodedValue = encodedIdentityComponent(claim.value());
        Optional<String> encodedClaimPath = issuerSubject
                ? Optional.of("")
                : encodedIdentityComponent(claim.path()).map(path -> path + ".");
        if (encodedAuthority.isEmpty() || encodedValue.isEmpty() || encodedClaimPath.isEmpty()) {
            return Optional.empty();
        }
        String prefix = issuer ? ISSUER_CLAIM_PRINCIPAL_ID_PREFIX : NAMESPACE_PRINCIPAL_ID_PREFIX;
        if (issuerSubject) {
            prefix = ISSUER_SUBJECT_PRINCIPAL_ID_PREFIX;
        }
        return Optional.of(new PrincipalIdentity(prefix
                                                         + encodedAuthority.orElseThrow()
                                                         + "."
                                                         + encodedClaimPath.orElseThrow()
                                                         + encodedValue.orElseThrow(),
                                                 claim.value()));
    }

    private static Optional<String> encodedIdentityComponent(String value) {
        // Do not silently replace unpaired surrogates: replacement would collapse distinct identity values.
        if (value.isBlank() || !StandardCharsets.UTF_8.newEncoder().canEncode(value)) {
            return Optional.empty();
        }
        return Optional.of(BASE64_URL_ENCODER.encodeToString(value.getBytes(StandardCharsets.UTF_8)));
    }

    private static Optional<String> firstClaimValue(JsonObject claims, List<String> claimPaths) {
        return firstClaimValue(claims::value, claimPaths);
    }

    private static Optional<String> firstClaimValue(Map<String, JsonValue> claims, List<String> claimPaths) {
        return firstClaimValue(name -> Optional.ofNullable(claims.get(name)), claimPaths);
    }

    private static Optional<String> firstClaimValue(ClaimSource claims, List<String> claimPaths) {
        return firstClaim(claims, claimPaths).map(SelectedClaim::value);
    }

    private static Optional<SelectedClaim> firstClaim(ClaimSource claims, List<String> claimPaths) {
        return claimPaths.stream()
                .map(claimPath -> claimValue(claims, claimPath)
                        .flatMap(OidcSubjectMapper::stringValue)
                        .filter(value -> !value.isBlank())
                        .map(value -> new SelectedClaim(claimPath, value)))
                .flatMap(Optional::stream)
                .findFirst();
    }

    private static Optional<String> stringValue(JsonValue value) {
        if (value.type() == JsonValueType.STRING) {
            return Optional.of(value.asString().value());
        }
        return Optional.empty();
    }

    private static List<String> roleClaimValues(JsonObject claims, OidcSubjectMappingConfig subjectMapping) {
        return claimValues(claims, subjectMapping.roleClaimPaths());
    }

    private static List<String> roleClaimValues(Map<String, JsonValue> claims,
                                                OidcSubjectMappingConfig subjectMapping) {
        return claimValues(claims, subjectMapping.roleClaimPaths());
    }

    private static List<String> scopeClaimValues(JsonObject claims, OidcSubjectMappingConfig subjectMapping) {
        return scopeClaimValues(claims::value, subjectMapping);
    }

    private static List<String> scopeClaimValues(Map<String, JsonValue> claims,
                                                 OidcSubjectMappingConfig subjectMapping) {
        return scopeClaimValues(name -> Optional.ofNullable(claims.get(name)), subjectMapping);
    }

    private static List<String> scopeClaimValues(ClaimSource claims, OidcSubjectMappingConfig subjectMapping) {
        return subjectMapping.scopeClaimPaths()
                .stream()
                .map(claimPath -> scopeClaimValues(claims, claimPath))
                .flatMap(List::stream)
                .distinct()
                .toList();
    }

    private static List<String> scopeClaimValues(ClaimSource claims, String claimPath) {
        return claimValue(claims, claimPath)
                .map(value -> OidcScopeSupport.scopeClaimValues(value,
                                                                "scope claim " + claimPath,
                                                                "scope".equals(claimPath)))
                .orElseGet(List::of);
    }

    private static List<String> claimValues(JsonObject claims, List<String> claimPaths) {
        return claimValues(claims::value, claimPaths);
    }

    private static List<String> claimValues(Map<String, JsonValue> claims,
                                            List<String> claimPaths) {
        return claimValues(name -> Optional.ofNullable(claims.get(name)), claimPaths);
    }

    private static List<String> claimValues(ClaimSource claims, List<String> claimPaths) {
        return claimPaths.stream()
                .map(claimPath -> claimValue(claims, claimPath))
                .flatMap(Optional::stream)
                .flatMap(OidcSubjectMapper::stringValues)
                .filter(value -> !value.isBlank())
                .distinct()
                .toList();
    }

    private static Optional<JsonValue> claimValue(ClaimSource claims, String claimPath) {
        String[] segments = claimPath.split("\\.");
        if (segments.length == 0 || segments[0].isBlank()) {
            return Optional.empty();
        }
        return claims.value(segments[0])
                .flatMap(value -> claimValue(value, segments));
    }

    private static Optional<JsonValue> claimValue(JsonValue firstSegmentValue, String[] segments) {
        JsonValue current = firstSegmentValue;
        for (int i = 1; i < segments.length; i++) {
            if (current == null || current.type() != JsonValueType.OBJECT || segments[i].isBlank()) {
                return Optional.empty();
            }
            current = current.asObject()
                    .value(segments[i])
                    .orElse(null);
        }
        return Optional.ofNullable(current);
    }

    private static Stream<String> stringValues(JsonValue value) {
        if (value.type() == JsonValueType.STRING) {
            return Stream.of(value.asString().value());
        }
        if (value.type() == JsonValueType.ARRAY) {
            return value.asArray()
                    .values()
                    .stream()
                    .filter(item -> item.type() == JsonValueType.STRING)
                    .map(item -> item.asString().value());
        }
        return Stream.empty();
    }

    private static void addRoles(Subject.Builder subjectBuilder, List<String> roles) {
        roles.forEach(role -> subjectBuilder.addGrant(Role.create(role)));
    }

    private static void addScope(Subject.Builder subjectBuilder, String scope) {
        subjectBuilder.addGrant(Grant.builder()
                                        .name(scope)
                                        .type("scope")
                                        .build());
    }

    @FunctionalInterface
    private interface ClaimSource {
        Optional<JsonValue> value(String name);
    }

    private record SelectedClaim(String path, String value) {
    }

    private record PrincipalIdentity(String id, String value) {
    }
}
