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

package io.helidon.security.providers.oidc.next.spi;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import io.helidon.config.NamedService;

/**
 * Stores the revocation information required by OpenID Connect Back-Channel Logout.
 * <p>
 * Implementations shared by several server instances must order authorization checkpoints, event application, and
 * session creation atomically and make the result consistently visible across instances. An implementation that promises
 * continuous logout enforcement must change its incarnation and reject previously issued sessions if it loses revocation
 * records. The built-in process-local store deliberately forgets revocations on restart and accepts still-valid browser
 * cookies; it cannot offer that guarantee across restarts or replicas. Do not silently evict a live revocation marker
 * within a store's lifetime. The caller owns an application-supplied store's lifecycle; the OIDC provider owns its
 * built-in in-memory store.
 * <p>
 * Helidon validates each Logout Token before calling {@link #revoke(LogoutEvent, Instant)}. This SPI must not accept
 * JWTs, route HTTP requests, or perform token validation itself.
 * Configured implementations should override {@link #type()} with their provider configuration key and
 * {@link #name()} with their configured instance name. Programmatically supplied stores may use the defaults.
 */
public interface OidcBackChannelLogoutStore extends NamedService {
    @Override
    default String name() {
        return "oidc-back-channel-logout-store";
    }

    @Override
    default String type() {
        return "custom";
    }

    /**
     * Capture an opaque checkpoint when starting an authorization request. The caller binds it to the protected
     * request cookie and supplies it to {@link #beginSession(Identity, String)} after validating the ID Token.
     * Checkpoints and subject-only revocations must be ordered by this store, not by the OP's second-resolution
     * {@code iat} claims or clocks on different RP instances. A shared store must recognize its checkpoints on every
     * instance using it.
     *
     * @param tenantId tenant starting the request
     * @param issuer exact OP issuer
     * @return a non-blank checkpoint
     */
    String authorizationCheckpoint(String tenantId, String issuer);

    /**
     * Establish a newly authenticated session only if no subject-wide logout for its tenant, issuer, and subject was
     * recorded after the authorization checkpoint. If the order cannot be established in the presence of a relevant
     * logout, reject the request. Maintain the returned subject generation until all cookies containing it have expired,
     * unless this store is deliberately volatile and is restarted. The caller checks revocation before storing the
     * returned marker in its protected browser cookie.
     *
     * @param identity identity of the new session
     * @param authorizationCheckpoint checkpoint from the protected authorization request cookie
     * @return store marker bound to this session, or empty when the request was invalidated by a logout
     */
    Optional<Marker> beginSession(Identity identity, String authorizationCheckpoint);

    /**
     * Check whether a browser session has been revoked by a session-specific or subject-wide Logout Token. Shared
     * stores can reject a previous incarnation if they lose their records; the built-in volatile store instead permits
     * still-valid cookies after restart. Fail with an exception if the store cannot answer reliably while running.
     *
     * @param session protected browser session to check
     * @return whether it was revoked
     */
    boolean revoked(Session session);

    /**
     * Atomically record a validated Logout Token. Retries with the same tenant/issuer/JWT ID must be idempotent;
     * recording the same event twice cannot invalidate a login established after its first delivery while the store
     * retains that JWT ID. The revocation must remain visible until {@code retainUntil}, and the JWT ID must be
     * remembered while the token remains valid, including the caller's accepted clock skew. The built-in volatile
     * store cannot recognize a replay after restart; use a durable shared store when cross-restart idempotency matters.
     * A different event reusing the same JWT ID must fail rather than be acknowledged without revocation.
     * Throw on storage failure instead of acknowledging an event that was not recorded.
     *
     * @param event validated Logout Token identity
     * @param retainUntil later of the affected browser sessions' expiry, pending authorization request expiry, and
     *                    the Logout Token's acceptance window
     */
    void revoke(LogoutEvent event, Instant retainUntil);

    /**
     * Stable identity of a local session as issued by the OP (not a mapped application principal).
     *
     * @param tenantId tenant owning the session
     * @param issuer exact OP issuer
     * @param subject OP subject
     * @param sid OP session ID when issued
     * @param expiresAt absolute browser-session expiration
     */
    record Identity(String tenantId,
                    String issuer,
                    String subject,
                    Optional<String> sid,
                    Instant expiresAt) {
        /**
         * Create a stable OP identity.
         *
         * @param tenantId tenant owning the session
         * @param issuer exact OP issuer
         * @param subject OP subject
         * @param sid OP session ID when issued
         * @param expiresAt absolute browser-session expiration
         */
        public Identity {
            Objects.requireNonNull(tenantId);
            Objects.requireNonNull(issuer);
            Objects.requireNonNull(subject);
            Objects.requireNonNull(sid);
            Objects.requireNonNull(expiresAt);
        }
    }

    /**
     * Store incarnation and per-subject generation captured at authentication.
     *
     * @param incarnation identifies the store lifetime; a shared store can reject older incarnations after data loss
     * @param subjectGeneration changes on subject-only logout
     */
    record Marker(String incarnation, String subjectGeneration) {
        /**
         * Create a marker from a reliable store lookup.
         *
         * @param incarnation identifies the store lifetime
         * @param subjectGeneration changes on subject-only logout
         */
        public Marker {
            Objects.requireNonNull(incarnation);
            Objects.requireNonNull(subjectGeneration);
            if (incarnation.isBlank() || subjectGeneration.isBlank()) {
                throw new IllegalArgumentException("OIDC logout store marker must not be blank");
            }
        }
    }

    /**
     * Protected browser-session identity and store marker.
     *
     * @param identity OP identity from the protected cookie
     * @param marker store version captured when the session was established
     */
    record Session(Identity identity, Marker marker) {
        /**
         * Create a protected browser session.
         *
         * @param identity OP identity from the protected cookie
         * @param marker store version captured when the session was established
         */
        public Session {
            Objects.requireNonNull(identity);
            Objects.requireNonNull(marker);
        }
    }

    /**
     * Identity of a cryptographically validated Logout Token. Only the core creates this value from an OP token.
     *
     * @param tenantId tenant owning the OP client
     * @param issuer exact OP issuer
     * @param subject optional OP subject
     * @param sid optional OP session ID
     * @param jwtId mandatory Logout Token identifier
     * @param issuedAt mandatory OP Logout Token issued-at time
     * @param expiresAt mandatory OP Logout Token expiration time
     */
    record LogoutEvent(String tenantId,
                       String issuer,
                       Optional<String> subject,
                       Optional<String> sid,
                       String jwtId,
                       Instant issuedAt,
                       Instant expiresAt) {
        /**
         * Create the identity of a validated Logout Token.
         *
         * @param tenantId tenant owning the OP client
         * @param issuer exact OP issuer
         * @param subject optional OP subject
         * @param sid optional OP session ID
         * @param jwtId mandatory Logout Token identifier
         * @param issuedAt mandatory OP Logout Token issued-at time
         * @param expiresAt mandatory OP Logout Token expiration time
         */
        public LogoutEvent {
            Objects.requireNonNull(tenantId);
            Objects.requireNonNull(issuer);
            Objects.requireNonNull(subject);
            Objects.requireNonNull(sid);
            Objects.requireNonNull(jwtId);
            Objects.requireNonNull(issuedAt);
            Objects.requireNonNull(expiresAt);
            if (subject.isEmpty() && sid.isEmpty()) {
                throw new IllegalArgumentException("Logout Token must contain sub or sid");
            }
        }
    }
}
