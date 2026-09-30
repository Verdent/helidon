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

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Resolves and validates Token Endpoint metadata needed only by request-time outbound policies.
 * <p>
 * Tenant initialization cannot see an {@link OidcOutboundPolicy} supplied later through an endpoint configuration. A
 * tenant that otherwise needs no Token Endpoint therefore remains ready without loading well-known metadata. The first
 * outbound token cache miss resolves that metadata here. One fair, interruptible single-flight slot per configured
 * tenant publishes the result to every grant and retains successful metadata for this resolver's lifetime.
 * <p>
 * The provider's configured tenant map bounds slot cardinality. An LRU is deliberately not used: eviction could discard
 * an active resolution or a successfully published provider-lifetime result and permit duplicate discovery.
 * <p>
 * A transient load failure is retained until the tenant initialization retry interval elapses. A deterministic metadata
 * failure is retained permanently. Grant-specific capability validation happens after shared resolution so unsupported
 * Client Credentials Grant metadata does not prevent the same tenant from using Token Exchange, or vice versa.
 * <p>
 * Production callers enter resolution only from an elected Client Credentials or Token Exchange loader, after that
 * loader has acquired its tenant-owned active permit. Callers reaching this slot are therefore bounded by the combined
 * active limits of those grants; same-key token followers wait outside the resolver under their grant's queue bound.
 * Keep that admission boundary when adding callers rather than placing unadmitted remote work before it.
 */
final class OidcOutboundMetadataResolver {
    private final Clock clock;
    private final ConcurrentMap<String, MetadataSlot> tenantSlots = new ConcurrentHashMap<>();

    OidcOutboundMetadataResolver() {
        this(Clock.systemUTC());
    }

    OidcOutboundMetadataResolver(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    OidcEndpointClient clientCredentialsEndpointClient(OidcTenantContext tenantContext) {
        ResolvedEndpoint resolved = resolve(tenantContext);
        OidcTenantContextFactory.validateClientCredentialsGrantMetadata(tenantContext.tenantConfig(),
                                                                        resolved.metadata());
        return resolved.endpointClient();
    }

    OidcEndpointClient tokenExchangeEndpointClient(OidcTenantContext tenantContext) {
        ResolvedEndpoint resolved = resolve(tenantContext);
        OidcTenantContextFactory.validateTokenExchangeMetadata(tenantContext.tenantConfig(), resolved.metadata());
        return resolved.endpointClient();
    }

    private ResolvedEndpoint resolve(OidcTenantContext tenantContext) {
        OidcProviderMetadata metadata = tenantContext.metadata();
        if (metadata.tokenEndpointUri().isPresent()
                || metadata.wellKnownMetadataLoaded()
                || metadata.wellKnownUri().isEmpty()) {
            return new ResolvedEndpoint(metadata, tenantContext.endpointClient());
        }
        return tenantSlots.computeIfAbsent(tenantContext.tenantId(), _ -> new MetadataSlot(clock))
                .resolve(tenantContext);
    }

    private static final class MetadataSlot {
        private final Clock clock;
        private final ReentrantLock resolutionLock = new ReentrantLock(true);
        private volatile MetadataState state = MetadataState.empty();

        private MetadataSlot(Clock clock) {
            this.clock = clock;
        }

        private ResolvedEndpoint resolve(OidcTenantContext tenantContext) {
            MetadataState current = state;
            if (current.reusable(clock.instant())) {
                return current.publishedOutcome();
            }
            lockInterruptibly();
            try {
                current = state;
                if (current.reusable(clock.instant())) {
                    return current.publishedOutcome();
                }
                try {
                    OidcProviderMetadata metadata = new OidcProviderMetadataLoader(tenantContext.webClient())
                            .load(tenantContext.metadata(),
                                  tenantContext.tenantConfig().endpoints().tlsRequired()
                                          || OidcClientAuthenticationSupport.outboundMutualTls(
                                                  tenantContext.tenantConfig()));
                    ResolvedEndpoint resolved = new ResolvedEndpoint(
                            metadata,
                            new OidcEndpointClient(tenantContext.tenantConfig(), metadata, tenantContext.webClient()));
                    state = MetadataState.success(resolved);
                    return resolved;
                } catch (OidcProviderMetadataLoader.RetryableDiscoveryException e) {
                    state = MetadataState.retryableFailure(
                            e,
                            clock.instant().plus(tenantContext.tenantConfig().initializationRetryInterval()));
                    throw e;
                } catch (RuntimeException e) {
                    state = MetadataState.permanentFailure(e);
                    throw e;
                }
            } finally {
                resolutionLock.unlock();
            }
        }

        private void lockInterruptibly() {
            try {
                resolutionLock.lockInterruptibly();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting for outbound OIDC metadata", e);
            }
        }
    }

    private record ResolvedEndpoint(OidcProviderMetadata metadata, OidcEndpointClient endpointClient) {
    }

    private record MetadataState(ResolvedEndpoint resolved, RuntimeException failure, Instant retryAfter) {
        private static MetadataState empty() {
            return new MetadataState(null, null, null);
        }

        private static MetadataState success(ResolvedEndpoint resolved) {
            return new MetadataState(resolved, null, null);
        }

        private static MetadataState retryableFailure(RuntimeException failure, Instant retryAfter) {
            return new MetadataState(null, failure, retryAfter);
        }

        private static MetadataState permanentFailure(RuntimeException failure) {
            return new MetadataState(null, failure, null);
        }

        private boolean reusable(Instant now) {
            return resolved != null || (failure != null && (retryAfter == null || now.isBefore(retryAfter)));
        }

        private ResolvedEndpoint publishedOutcome() {
            if (resolved != null) {
                return resolved;
            }
            throw Objects.requireNonNull(failure);
        }
    }
}
