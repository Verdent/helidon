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

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import io.helidon.common.uri.UriHost;
import io.helidon.security.providers.common.OutboundConfig;
import io.helidon.webclient.api.ConnectedSocketChannelInfo;
import io.helidon.webclient.api.ConnectedSocketInfo;
import io.helidon.webclient.api.ConnectionListener;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;

final class OidcWebClientFactory {
    private static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration WEBCLIENT_DEFAULT_SOCKET_READ_TIMEOUT =
            WebClientConfig.create().socketOptions().readTimeout();

    private OidcWebClientFactory() {
    }

    static WebClient create(OidcTenantConfig tenantConfig) {
        WebClientConfig configured = tenantConfig.webClient();
        /*
         * Provider-owned protocol traffic already applies its required endpoint authentication explicitly. Allowing
         * WebClientSecurity to route these requests through OIDC outbound security can re-enter the same tenant
         * initialization or token single-flight operation and make the leader wait on itself.
         */
        WebClientConfig.Builder builder = WebClientConfig.builder()
                .from(configured)
                .putProperty(OutboundConfig.PROPERTY_DISABLE_OUTBOUND, Boolean.TRUE.toString());
        if (signedRequestObjectWithParPossible(tenantConfig)) {
            // Discovery may select the PAR endpoint; it must use the same identity policy from the outset.
            // A connection opened by a non-strict WebClient must not be reused by this tenant.
            builder.shareConnectionCache(false)
                    .connectionListener(strictConnectionListener(configured.connectionListener()));
        }
        if (configured.readTimeout().isEmpty()
                && WEBCLIENT_DEFAULT_SOCKET_READ_TIMEOUT.equals(configured.socketOptions().readTimeout())) {
            builder.readTimeout(DEFAULT_READ_TIMEOUT);
        }
        return WebClient.create(builder.buildPrototype());
    }

    private static boolean signedRequestObjectWithParPossible(OidcTenantConfig tenantConfig) {
        return tenantConfig.authorizationCode()
                .filter(OidcAuthorizationCodeConfig::enabled)
                .filter(code -> code.pushedAuthorizationRequests() != OidcPushedAuthorizationRequestMode.DISABLED)
                .map(OidcAuthorizationCodeConfig::requestObject)
                .filter(requestObject -> requestObject.mode() != OidcRequestObjectMode.DISABLED
                        && requestObject.signingJwk().isPresent())
                .isPresent();
    }

    private static ConnectionListener strictConnectionListener(ConnectionListener configured) {
        return new ConnectionListener() {
            @Override
            public void socketConnected(ConnectedSocketInfo socketInfo) throws IOException {
                configured.socketConnected(socketInfo);
            }

            @Override
            public void socketChannelConnected(ConnectedSocketChannelInfo socketInfo) throws IOException {
                configured.socketChannelConnected(socketInfo);
            }

            @Override
            public void tlsHandshakeCompleted(SSLSession session) {
                verifyDnsId(session);
                configured.tlsHandshakeCompleted(session);
            }
        };
    }

    private static void verifyDnsId(SSLSession session) {
        String peerHost = session.getPeerHost();
        if (peerHost == null) {
            throw new IllegalStateException("TLS peer has no DNS host for Request Object URI verification");
        }
        UriHost expectedHost;
        try {
            expectedHost = UriHost.create(peerHost);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("TLS peer has an invalid DNS host for Request Object URI verification", e);
        }
        if (expectedHost.kind() != UriHost.Kind.DNS) {
            throw new IllegalStateException("Request Object URI TLS peer must be identified by a DNS name");
        }

        Certificate[] certificates;
        try {
            certificates = session.getPeerCertificates();
        } catch (SSLPeerUnverifiedException e) {
            throw new IllegalStateException("Request Object URI TLS peer has no verified certificate", e);
        }
        if (certificates.length == 0 || !(certificates[0] instanceof X509Certificate leaf)) {
            throw new IllegalStateException("Request Object URI TLS peer has no X.509 server certificate");
        }
        Collection<List<?>> subjectAlternativeNames;
        try {
            subjectAlternativeNames = leaf.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            throw new IllegalStateException("Request Object URI TLS peer has invalid certificate identities", e);
        }
        if (subjectAlternativeNames != null) {
            for (List<?> name : subjectAlternativeNames) {
                // X.509 subjectAltName type 2 is dNSName; no CN-ID or other identifier can authenticate this peer.
                if (name.size() >= 2
                        && name.get(0) instanceof Integer type && type == 2
                        && name.get(1) instanceof String dnsId
                        && matchesDnsId(expectedHost, dnsId)) {
                    return;
                }
            }
        }
        throw new IllegalStateException("Request Object URI TLS peer certificate has no matching DNS subject alternative name");
    }

    private static boolean matchesDnsId(UriHost expectedHost, String dnsId) {
        try {
            if (dnsId.indexOf('*') < 0) {
                return expectedHost.equals(UriHost.create(dnsId));
            }
            if (!dnsId.startsWith("*.") || dnsId.indexOf('*', 1) >= 0) {
                return false;
            }
            UriHost suffix = UriHost.create(dnsId.substring(2));
            String host = expectedHost.value();
            int firstDot = host.indexOf('.');
            return suffix.kind() == UriHost.Kind.DNS
                    && firstDot > 0
                    && host.substring(firstDot + 1).equals(suffix.value());
        } catch (IllegalArgumentException _) {
            return false;
        }
    }
}
