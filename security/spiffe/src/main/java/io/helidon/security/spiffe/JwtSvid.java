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

package io.helidon.security.spiffe;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;

/**
 * Parsed SPIFFE JWT-SVID.
 */
public final class JwtSvid implements SpiffeSvid {
    private final String tokenContent;
    private final SignedJwt signedJwt;
    private final Jwt jwt;
    private final SpiffeId spiffeId;
    private final List<String> audiences;
    private final Instant expiresAt;
    private final Optional<Instant> notBefore;
    private final Optional<Instant> issuedAt;

    private JwtSvid(String tokenContent,
                    SignedJwt signedJwt,
                    Jwt jwt,
                    SpiffeId spiffeId,
                    List<String> audiences,
                    Instant expiresAt,
                    Optional<Instant> notBefore,
                    Optional<Instant> issuedAt) {
        this.tokenContent = tokenContent;
        this.signedJwt = signedJwt;
        this.jwt = jwt;
        this.spiffeId = spiffeId;
        this.audiences = List.copyOf(audiences);
        this.expiresAt = expiresAt;
        this.notBefore = notBefore;
        this.issuedAt = issuedAt;
    }

    /**
     * Parse a JWT-SVID.
     *
     * @param tokenContent serialized signed JWT
     * @return JWT-SVID
     * @throws SpiffeException if the token is not a valid JWT-SVID
     */
    public static JwtSvid parse(String tokenContent) {
        Objects.requireNonNull(tokenContent, "JWT-SVID token content must not be null");
        try {
            SignedJwt signedJwt = SignedJwt.parseToken(tokenContent);
            Jwt jwt = signedJwt.getJwt();
            SpiffeId spiffeId = SpiffeId.parse(jwt.subject()
                                                       .orElseThrow(() -> new SpiffeException(
                                                               "JWT-SVID must contain a subject claim")));
            if (spiffeId.isRoot()) {
                throw new SpiffeException("JWT-SVID subject must include a workload path");
            }

            List<String> audiences = jwt.audience()
                    .filter(it -> !it.isEmpty())
                    .orElseThrow(() -> new SpiffeException("JWT-SVID must contain at least one audience"));
            Instant expiresAt = jwt.expirationTime()
                    .orElseThrow(() -> new SpiffeException("JWT-SVID must contain an expiration time"));

            return new JwtSvid(tokenContent,
                               signedJwt,
                               jwt,
                               spiffeId,
                               audiences,
                               expiresAt,
                               jwt.notBefore(),
                               jwt.issueTime());
        } catch (SpiffeException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new SpiffeException("JWT-SVID is invalid", e);
        }
    }

    /**
     * Serialized token content.
     *
     * @return token content
     */
    public String tokenContent() {
        return tokenContent;
    }

    /**
     * Signed JWT.
     *
     * @return signed JWT
     */
    public SignedJwt signedJwt() {
        return signedJwt;
    }

    /**
     * JWT claims.
     *
     * @return JWT
     */
    public Jwt jwt() {
        return jwt;
    }

    @Override
    public SpiffeId spiffeId() {
        return spiffeId;
    }

    /**
     * JWT audience values.
     *
     * @return audience values
     */
    public List<String> audiences() {
        return audiences;
    }

    @Override
    public Instant expiresAt() {
        return expiresAt;
    }

    @Override
    public Optional<Instant> notBefore() {
        return notBefore;
    }

    /**
     * Issued-at time.
     *
     * @return issued-at time
     */
    public Optional<Instant> issuedAt() {
        return issuedAt;
    }
}
