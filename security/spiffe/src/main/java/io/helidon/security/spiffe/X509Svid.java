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

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Parsed SPIFFE X.509-SVID.
 */
public final class X509Svid implements SpiffeSvid {
    private static final int SUBJECT_ALT_NAME_URI = 6;

    private final X509Certificate leafCertificate;
    private final List<X509Certificate> certificateChain;
    private final SpiffeId spiffeId;

    private X509Svid(X509Certificate leafCertificate, List<X509Certificate> certificateChain, SpiffeId spiffeId) {
        this.leafCertificate = leafCertificate;
        this.certificateChain = List.copyOf(certificateChain);
        this.spiffeId = spiffeId;
    }

    /**
     * Create an X.509-SVID from a certificate chain.
     *
     * @param certificateChain certificate chain with the leaf certificate first
     * @return X.509-SVID
     * @throws SpiffeException if the chain does not contain exactly one SPIFFE URI SAN on the leaf certificate
     */
    public static X509Svid create(List<X509Certificate> certificateChain) {
        Objects.requireNonNull(certificateChain, "Certificate chain must not be null");
        if (certificateChain.isEmpty()) {
            throw new SpiffeException("X.509-SVID certificate chain must not be empty");
        }
        List<X509Certificate> chain = List.copyOf(certificateChain);
        X509Certificate leaf = chain.get(0);
        SpiffeId spiffeId = extractSpiffeId(leaf);
        if (spiffeId.isRoot()) {
            throw new SpiffeException("X.509-SVID SPIFFE ID must include a workload path");
        }
        return new X509Svid(leaf, chain, spiffeId);
    }

    /**
     * Leaf certificate.
     *
     * @return leaf certificate
     */
    public X509Certificate leafCertificate() {
        return leafCertificate;
    }

    /**
     * Certificate chain with the leaf certificate first.
     *
     * @return certificate chain
     */
    public List<X509Certificate> certificateChain() {
        return certificateChain;
    }

    @Override
    public SpiffeId spiffeId() {
        return spiffeId;
    }

    @Override
    public Optional<Instant> notBefore() {
        return Optional.of(leafCertificate.getNotBefore().toInstant());
    }

    @Override
    public Instant expiresAt() {
        return leafCertificate.getNotAfter().toInstant();
    }

    private static SpiffeId extractSpiffeId(X509Certificate certificate) {
        List<String> spiffeUris = spiffeUriSubjectAltNames(certificate);
        if (spiffeUris.isEmpty()) {
            throw new SpiffeException("X.509-SVID leaf certificate must contain a SPIFFE URI SAN");
        }
        if (spiffeUris.size() > 1) {
            throw new SpiffeException("X.509-SVID leaf certificate must contain exactly one SPIFFE URI SAN");
        }
        return SpiffeId.parse(spiffeUris.get(0));
    }

    private static List<String> spiffeUriSubjectAltNames(X509Certificate certificate) {
        Collection<List<?>> subjectAltNames;
        try {
            subjectAltNames = certificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            throw new SpiffeException("Failed to parse X.509-SVID subject alternative names", e);
        }
        if (subjectAltNames == null) {
            return List.of();
        }

        List<String> result = new LinkedList<>();
        for (List<?> subjectAltName : subjectAltNames) {
            if (subjectAltName.size() < 2 || !(subjectAltName.get(0) instanceof Number type)) {
                continue;
            }
            if (type.intValue() != SUBJECT_ALT_NAME_URI || !(subjectAltName.get(1) instanceof String uri)) {
                continue;
            }
            if (uri.startsWith(SpiffeId.SCHEME + "://")) {
                result.add(uri);
            }
        }
        return result;
    }
}
