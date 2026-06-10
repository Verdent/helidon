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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import io.helidon.common.configurable.Resource;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.json.JsonValue;
import io.helidon.json.JsonValueType;
import io.helidon.security.jwt.jwk.Jwk;
import io.helidon.security.jwt.jwk.JwkKeys;

/**
 * Loader for SPIFFE bundle documents.
 */
public final class SpiffeBundleLoader {
    /**
     * SPIFFE JWK use value for JWT-SVID signing keys.
     */
    public static final String USE_JWT_SVID = "jwt-svid";
    /**
     * SPIFFE JWK use value for X.509-SVID authorities.
     */
    public static final String USE_X509_SVID = "x509-svid";

    private static final Set<String> FORBIDDEN_PRIVATE_JWK_PARAMETERS =
            Set.of("k", "d", "p", "q", "dp", "dq", "qi", "oth");
    private static final Base64.Decoder X509_DECODER = Base64.getMimeDecoder();

    private SpiffeBundleLoader() {
    }

    /**
     * Load a SPIFFE bundle from a JSON object.
     *
     * @param trustDomain trust domain this bundle belongs to
     * @param json bundle JSON document
     * @return SPIFFE bundle
     */
    public static SpiffeBundle load(SpiffeTrustDomain trustDomain, JsonObject json) {
        Objects.requireNonNull(trustDomain, "Trust domain must not be null");
        Objects.requireNonNull(json, "Bundle JSON must not be null");

        JwkKeys.Builder jwtKeysBuilder = JwkKeys.builder();
        List<X509Certificate> x509Authorities = new LinkedList<>();

        json.arrayValue("keys")
                .orElseThrow(() -> new SpiffeException("SPIFFE bundle JSON must contain a keys array"))
                .values()
                .stream()
                .filter(value -> value.type() == JsonValueType.OBJECT)
                .map(JsonValue::asObject)
                .forEach(key -> addKey(jwtKeysBuilder, x509Authorities, key));

        return SpiffeBundle.builder(trustDomain)
                .jwtSvidKeys(jwtKeysBuilder.build())
                .x509Authorities(x509Authorities)
                .build();
    }

    /**
     * Load a SPIFFE bundle from a resource.
     * <p>
     * This method parses the supplied resource content. HTTP/HTTPS retrieval, when needed by an integration,
     * should be performed with Helidon WebClient before passing the JSON document here.
     *
     * @param trustDomain trust domain this bundle belongs to
     * @param resource JSON resource
     * @return SPIFFE bundle
     */
    public static SpiffeBundle load(SpiffeTrustDomain trustDomain, Resource resource) {
        Objects.requireNonNull(resource, "Resource must not be null");
        try (InputStream inputStream = resource.stream()) {
            return load(trustDomain, JsonParser.create(inputStream).readJsonObject());
        } catch (IOException e) {
            throw new SpiffeException("Failed to close SPIFFE bundle resource", e);
        } catch (RuntimeException e) {
            throw new SpiffeException("Failed to load SPIFFE bundle resource", e);
        }
    }

    private static void addKey(JwkKeys.Builder jwtKeysBuilder,
                               List<X509Certificate> x509Authorities,
                               JsonObject key) {
        validateNoPrivateKeyMaterial(key);

        String use = key.stringValue(Jwk.PARAM_USE).orElse(null);
        if (USE_JWT_SVID.equals(use)) {
            jwtKeysBuilder.addKey(Jwk.create(JsonObject.builder()
                                             .from(key)
                                             .set(Jwk.PARAM_USE, Jwk.USE_SIGNATURE)
                                             .build()));
        } else if (USE_X509_SVID.equals(use)) {
            x509Authorities.addAll(parseX509Authorities(key));
        }
    }

    private static void validateNoPrivateKeyMaterial(JsonObject key) {
        if (key.stringValue(Jwk.PARAM_KEY_TYPE).filter(Jwk.KEY_TYPE_OCT::equals).isPresent()) {
            throw new SpiffeException("SPIFFE bundle must not contain symmetric JWKs");
        }
        for (String parameter : FORBIDDEN_PRIVATE_JWK_PARAMETERS) {
            if (key.containsKey(parameter)) {
                throw new SpiffeException("SPIFFE bundle must not contain private JWK parameter: " + parameter);
            }
        }
    }

    private static List<X509Certificate> parseX509Authorities(JsonObject key) {
        List<X509Certificate> result = new LinkedList<>();
        key.arrayValue("x5c")
                .orElseThrow(() -> new SpiffeException("SPIFFE X.509-SVID bundle key must contain x5c"))
                .values()
                .forEach(value -> result.add(parseCertificate(value.asString().value())));
        return result;
    }

    private static X509Certificate parseCertificate(String base64Der) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            byte[] bytes = X509_DECODER.decode(base64Der);
            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(bytes));
        } catch (IllegalArgumentException | CertificateException e) {
            throw new SpiffeException("Failed to parse SPIFFE X.509 certificate from bundle", e);
        }
    }
}
