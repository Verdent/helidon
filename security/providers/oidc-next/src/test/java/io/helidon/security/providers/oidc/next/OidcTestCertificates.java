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

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import io.helidon.common.socket.PeerInfo;

final class OidcTestCertificates {
    private OidcTestCertificates() {
    }

    static Certificate certificate(String value) {
        return new EncodedCertificate(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    static String thumbprint(Certificate certificate) {
        try {
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to calculate certificate thumbprint", e);
        }
    }

    static PeerInfo peerInfo(Certificate certificate) {
        return new TestPeerInfo(certificate);
    }

    private static final class EncodedCertificate extends Certificate {
        private final byte[] encoded;

        private EncodedCertificate(byte[] encoded) {
            super("X.509");
            this.encoded = Arrays.copyOf(encoded, encoded.length);
        }

        @Override
        public byte[] getEncoded() {
            return Arrays.copyOf(encoded, encoded.length);
        }

        @Override
        public void verify(PublicKey key) {
        }

        @Override
        public void verify(PublicKey key, String sigProvider) {
        }

        @Override
        public String toString() {
            return "EncodedCertificate";
        }

        @Override
        public PublicKey getPublicKey() {
            return null;
        }
    }

    private record TestPeerInfo(Certificate certificate) implements PeerInfo {
        @Override
        public SocketAddress address() {
            return InetSocketAddress.createUnresolved("client.example", 443);
        }

        @Override
        public String host() {
            return "client.example";
        }

        @Override
        public int port() {
            return 443;
        }

        @Override
        public Optional<Principal> tlsPrincipal() {
            return Optional.empty();
        }

        @Override
        public Optional<Certificate[]> tlsCertificates() {
            return Optional.of(new Certificate[] {certificate});
        }
    }
}
