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

import io.helidon.json.JsonValueType;
import io.helidon.security.jwt.Jwt;
import io.helidon.security.providers.oidc.next.spi.OidcBackChannelLogoutStore;

/**
 * Binds the OP's original identity to a protected browser session and checks revocation before using its credentials.
 */
final class OidcBackChannelSessionSupport {
    private static final String SID_CLAIM = "sid";

    private OidcBackChannelSessionSupport() {
    }

    static OidcBackChannelLogoutStore.Session begin(OidcLocalAuthenticationResult result,
                                                    OidcBackChannelLogoutStore store,
                                                    String authorizationCheckpoint,
                                                    boolean sessionRequired) {
        Jwt jwt = result.idToken().jwt();
        Optional<String> sid = sid(jwt, "OP ID Token");
        if (sessionRequired && sid.isEmpty()) {
            throw new IllegalArgumentException("OP ID Token does not include the required sid claim");
        }
        OidcBackChannelLogoutStore.Identity identity = new OidcBackChannelLogoutStore.Identity(
                result.tenantId(),
                jwt.issuer().orElseThrow(),
                jwt.subject().orElseThrow(),
                sid,
                result.expiresAt());
        OidcBackChannelLogoutStore.Session session;
        try {
            session = new OidcBackChannelLogoutStore.Session(
                    identity, store.beginSession(identity, authorizationCheckpoint)
                            .orElseThrow(SessionRevokedException::new));
            if (store.revoked(session)) {
                throw new SessionRevokedException();
            }
        } catch (SessionRevokedException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new StoreUnavailableException(e);
        }
        return session;
    }

    static boolean revoked(OidcLocalAuthenticationResult current, OidcBackChannelLogoutStore store) {
        Optional<OidcBackChannelLogoutStore.Session> binding = current.backChannelSession();
        if (binding.isEmpty()) {
            // An older cookie predating enabled Back-Channel Logout has no stable revocation binding.
            return true;
        }
        OidcBackChannelLogoutStore.Session session = binding.orElseThrow();
        Jwt jwt = current.idToken().jwt();
        if (!current.tenantId().equals(session.identity().tenantId())
                || !jwt.issuer().equals(Optional.of(session.identity().issuer()))
                || !jwt.subject().equals(Optional.of(session.identity().subject()))
                || !current.expiresAt().equals(session.identity().expiresAt())) {
            return true;
        }
        try {
            return store.revoked(session);
        } catch (RuntimeException e) {
            throw new StoreUnavailableException(e);
        }
    }

    static OidcBackChannelLogoutStore.Session afterRefresh(OidcLocalAuthenticationResult current,
                                                           Jwt refreshedIdToken,
                                                           OidcBackChannelLogoutStore store) {
        OidcBackChannelLogoutStore.Session original = current.backChannelSession().orElseThrow();
        Optional<String> newSid = sid(refreshedIdToken, "OP ID Token");
        if (newSid.isPresent() && original.identity().sid().isPresent()
                && !original.identity().sid().equals(newSid)) {
            // A refreshed ID Token can replace End-User claims, but silently changing the OP session ID would let
            // an in-flight logout notification for the original sid miss this browser session.
            throw new IllegalArgumentException("Refreshed ID Token changed the OP session ID");
        }
        OidcBackChannelLogoutStore.Session session = original;
        if (original.identity().sid().isEmpty() && newSid.isPresent()) {
            OidcBackChannelLogoutStore.Identity identity = original.identity();
            session = new OidcBackChannelLogoutStore.Session(new OidcBackChannelLogoutStore.Identity(
                    identity.tenantId(), identity.issuer(), identity.subject(), newSid,
                    identity.expiresAt()), original.marker());
        }
        try {
            if (store.revoked(original) || session != original && store.revoked(session)) {
                throw new SessionRevokedException();
            }
        } catch (SessionRevokedException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new StoreUnavailableException(e);
        }
        return session;
    }

    static Optional<String> sid(Jwt jwt, String tokenName) {
        return jwt.payloadClaimValue(SID_CLAIM)
                .map(value -> {
                    if (value.type() != JsonValueType.STRING) {
                        throw new IllegalArgumentException(tokenName + " sid claim must be a string");
                    }
                    String sessionId = value.asString().value();
                    if (sessionId.isBlank()) {
                        throw new IllegalArgumentException(tokenName + " sid claim must not be blank");
                    }
                    return sessionId;
                });
    }

    static final class SessionRevokedException extends RuntimeException {
    }

    static final class StoreUnavailableException extends RuntimeException {
        StoreUnavailableException(Throwable cause) {
            super("OIDC back-channel logout store is unavailable", cause);
        }
    }
}
