/*
 * Copyright (c) 2021, 2026 Oracle and/or its affiliates.
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

package io.helidon.security.jwt;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import io.helidon.common.Errors;
import io.helidon.common.configurable.Resource;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.security.jwt.EncryptedJwt.SupportedAlgorithm;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.jwt.jwk.JwkRSA;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.helidon.security.jwt.EncryptedJwt.SupportedEncryption;
import static io.helidon.security.jwt.EncryptedJwt.builder;
import static io.helidon.security.jwt.EncryptedJwt.parseToken;
import static io.helidon.security.jwt.EncryptedJwt.payloadBuilder;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Encrypted JWT tests.
 */
public class EncryptedJwtTest {

    private static JwkKeys jwkKeys;
    private static SignedJwt signedJwt;

    @BeforeAll
    public static void init() {
        jwkKeys = JwkKeys.builder()
                .resource(Resource.create("jwk_data.json"))
                .build();

        Jwt jwt = Jwt.builder()
                .addAudience("test")
                .email("unit@test.example")
                .algorithm("RS256")
                .keyId("cc34c0a0-bd5a-4a3c-a50d-a2a7db7643df")
                .issuer("unit-test")
                .build();

        signedJwt = SignedJwt.sign(jwt, jwkKeys);
    }

    @Test
    public void testDefaultHeaderCreation() {
        String kid = "RS_512";
        EncryptedJwt encryptedJwt = builder(signedJwt).jwks(jwkKeys, kid).build();
        JwtHeaders headers = encryptedJwt.headers();
        assertThat(headers.algorithm(), is(Optional.of(SupportedAlgorithm.RSA_OAEP.toString())));
        assertThat(headers.encryption(), is(Optional.of(SupportedEncryption.A256GCM.toString())));
        assertThat(headers.contentType(), is(Optional.of("JWT")));
        assertThat(headers.keyId(), is(Optional.of(kid)));

        headers = JwtHeaders.parseToken(encryptedJwt.token());
        assertThat(headers.algorithm(), is(Optional.of(SupportedAlgorithm.RSA_OAEP.toString())));
        assertThat(headers.encryption(), is(Optional.of(SupportedEncryption.A256GCM.toString())));
        assertThat(headers.contentType(), is(Optional.of("JWT")));
        assertThat(headers.keyId(), is(Optional.of(kid)));
    }

    @Test
    void testPayloadEncryptAndDecrypt() {
        byte[] expectedPayload = "{\"sub\":\"encrypted-user\"}".getBytes(StandardCharsets.UTF_8);
        byte[] sourcePayload = expectedPayload.clone();
        EncryptedJwt.Builder builder = payloadBuilder(sourcePayload)
                .jwks(jwkKeys, "RS_512");
        sourcePayload[0] = 'X';

        EncryptedJwt encryptedJwt = builder.build();

        assertThat(encryptedJwt.headers().contentType(), is(Optional.empty()));
        assertArrayEquals(expectedPayload, parseToken(encryptedJwt.token()).decryptPayload(jwkKeys));
    }

    @Test
    void testPayloadWithTamperedAuthenticationTagIsRejected() {
        EncryptedJwt encryptedJwt = payloadBuilder("payload".getBytes(StandardCharsets.UTF_8))
                .jwks(jwkKeys, "RS_512")
                .build();
        String[] tokenParts = encryptedJwt.token().split("\\.", -1);
        byte[] authenticationTag = Base64.getUrlDecoder().decode(tokenParts[4]);
        authenticationTag[0] ^= 1;
        tokenParts[4] = Base64.getUrlEncoder().withoutPadding().encodeToString(authenticationTag);
        String tamperedToken = String.join(".", tokenParts);

        assertThrows(JwtException.class, () -> parseToken(tamperedToken).decryptPayload(jwkKeys));
    }

    @Test
    void testOriginalProtectedHeaderIsUsedAsAdditionalAuthenticatedData() throws GeneralSecurityException {
        JwkRSA jwk = (JwkRSA) jwkKeys.forKeyId("RS_512").orElseThrow();
        byte[] payload = "{\"sub\":\"non-canonical-header\"}".getBytes(StandardCharsets.UTF_8);
        String protectedHeader = "{ \"enc\" : \"A256GCM\", \"kid\" : \"RS_512\", "
                + "\"alg\" : \"RSA-OAEP-256\" }";
        String protectedHeaderBase64 = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(protectedHeader.getBytes(StandardCharsets.UTF_8));

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey contentEncryptionKey = keyGenerator.generateKey();
        byte[] initializationVector = new byte[12];
        new SecureRandom().nextBytes(initializationVector);

        Cipher contentCipher = Cipher.getInstance("AES/GCM/NoPadding");
        contentCipher.init(Cipher.ENCRYPT_MODE, contentEncryptionKey, new GCMParameterSpec(128, initializationVector));
        contentCipher.updateAAD(protectedHeaderBase64.getBytes(StandardCharsets.US_ASCII));
        byte[] ciphertextAndTag = contentCipher.doFinal(payload);
        byte[] ciphertext = Arrays.copyOf(ciphertextAndTag, ciphertextAndTag.length - 16);
        byte[] authenticationTag = Arrays.copyOfRange(ciphertextAndTag, ciphertext.length, ciphertextAndTag.length);

        Cipher keyCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        keyCipher.init(Cipher.WRAP_MODE,
                       jwk.publicKey(),
                       new OAEPParameterSpec("SHA-256",
                                             "MGF1",
                                             MGF1ParameterSpec.SHA256,
                                             PSource.PSpecified.DEFAULT));
        byte[] encryptedKey = keyCipher.wrap(contentEncryptionKey);
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String token = protectedHeaderBase64 + "."
                + encoder.encodeToString(encryptedKey) + "."
                + encoder.encodeToString(initializationVector) + "."
                + encoder.encodeToString(ciphertext) + "."
                + encoder.encodeToString(authenticationTag);

        assertArrayEquals(payload, parseToken(token).decryptPayload(jwkKeys));
    }

    @Test
    public void testCustomHeaderCreation() {
        String kid = "RS_512";
        SupportedAlgorithm rsaAlgorithm = SupportedAlgorithm.RSA_OAEP_256;
        SupportedEncryption aesAlgorithm = SupportedEncryption.A256CBC_HS512;
        EncryptedJwt encryptedJwt = builder(signedJwt)
                .jwks(jwkKeys, kid)
                .algorithm(rsaAlgorithm)
                .encryption(aesAlgorithm)
                .build();
        JsonObject headers = encryptedJwt.headers().headerJsonObject();
        assertThat(headers.stringValue("alg"), is(Optional.of(rsaAlgorithm.toString())));
        assertThat(headers.stringValue("enc"), is(Optional.of(aesAlgorithm.toString())));
        assertThat(headers.stringValue("cty"), is(Optional.of("JWT")));
        assertThat(headers.stringValue("kid"), is(Optional.of(kid)));
    }

    @Test
    public void testDefaultEncryptAndDecrypt() {
        EncryptedJwt encryptedOne = builder(signedJwt).jwks(jwkKeys, "RS_512").build();
        EncryptedJwt encryptedSecond = builder(signedJwt).jwks(jwkKeys, "RS_512").build();
        assertThat(encryptedOne.token(), not(encryptedSecond.token()));

        EncryptedJwt encryptedJwt = parseToken(encryptedOne.token());
        SignedJwt decryptedOne = encryptedJwt.decrypt(jwkKeys);
        EncryptedJwt encryptedJwt2 = parseToken(encryptedSecond.token());
        SignedJwt decryptedTwo = encryptedJwt2.decrypt(jwkKeys);
        assertThat(decryptedOne.getJwt().headerJsonObject(), is(decryptedTwo.getJwt().headerJsonObject()));
    }

    @Test
    public void testCustomEncryptAndDecrypt() {
        EncryptedJwt encryptedOne = builder(signedJwt)
                .jwks(jwkKeys, "RS_512")
                .algorithm(SupportedAlgorithm.RSA_OAEP)
                .encryption(SupportedEncryption.A256CBC_HS512)
                .build();
        EncryptedJwt encryptedSecond = builder(signedJwt)
                .jwks(jwkKeys, "RS_512")
                .algorithm(SupportedAlgorithm.RSA_OAEP_256)
                .encryption(SupportedEncryption.A128CBC_HS256)
                .build();
        assertThat(encryptedOne.token(), not(encryptedSecond.token()));

        EncryptedJwt encryptedJwt = parseToken(encryptedOne.token());
        SignedJwt decryptedOne = encryptedJwt.decrypt(jwkKeys);
        EncryptedJwt encryptedJwt2 = parseToken(encryptedSecond.token());
        SignedJwt decryptedTwo = encryptedJwt2.decrypt(jwkKeys);

        assertThat(decryptedOne.getJwt().headerJsonObject(), is(decryptedTwo.getJwt().headerJsonObject()));
    }

    @Test
    void testUnsupportedRsaKeyManagementAlgorithmIsRejected() {
        String rsaPkcs1 = "RSA1_5";
        String headerBase64 = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(JwtHeaders.builder()
                                        .algorithm(rsaPkcs1)
                                        .encryption(SupportedEncryption.A256GCM.toString())
                                        .contentType("JWT")
                                        .keyId("RS_512")
                                        .build()
                                        .headerJsonObject()
                                        .toString()
                                        .getBytes(StandardCharsets.UTF_8));
        EncryptedJwt encryptedJwt = parseToken(headerBase64 + ".AA.AA.AA.AA");

        assertThat(encryptedJwt.headers().algorithm(), is(Optional.of(rsaPkcs1)));
        Errors.ErrorMessagesException exception =
                assertThrows(Errors.ErrorMessagesException.class, () -> encryptedJwt.decrypt(jwkKeys));
        assertThat(exception.getMessage(), containsString("Value of the claim alg not supported. alg: RSA1_5"));
    }

    @Test
    @SuppressWarnings("removal")
    void testUnsupportedRsaKeyManagementAlgorithmCannotBeUsedForEncryption() {
        JwtException exception = assertThrows(JwtException.class, () -> builder(signedJwt)
                .jwks(jwkKeys, "RS_512")
                .algorithm(SupportedAlgorithm.RSA1_5)
                .build());
        assertThat(exception.getMessage(), containsString("JWE key encryption algorithm is not supported: RSA1_5"));
    }

    @Test
    void testNimbusToHelidon() throws ParseException, JOSEException {
        JwkRSA jwk = (JwkRSA) jwkKeys.forKeyId("RS_512").orElseThrow();
        RSAPublicKey publicKey = (RSAPublicKey) jwk.publicKey();

        Payload payload = new Payload(SignedJWT.parse(signedJwt.tokenContent()));
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512);
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new RSAEncrypter(publicKey));
        String serializedJweFromNimbus = jweObject.serialize();

        EncryptedJwt encryptedJwt = parseToken(serializedJweFromNimbus);
        SignedJwt decrypted = encryptedJwt.decrypt(jwk);

        assertThat(decrypted.getJwt().payloadJsonObject(), is(signedJwt.getJwt().payloadJsonObject()));
    }

    @Test
    void testNimbusPayloadToHelidon() throws JOSEException {
        JwkRSA jwk = (JwkRSA) jwkKeys.forKeyId("RS_512").orElseThrow();
        RSAPublicKey publicKey = (RSAPublicKey) jwk.publicKey();
        String payload = "{\"sub\":\"nimbus-user\"}";

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
        JWEObject jweObject = new JWEObject(header, new Payload(payload));
        jweObject.encrypt(new RSAEncrypter(publicKey));

        byte[] decrypted = parseToken(jweObject.serialize()).decryptPayload(jwk);

        assertThat(new String(decrypted, StandardCharsets.UTF_8), is(payload));
    }

    @Test
    void testHelidonToNimbus() throws ParseException, JOSEException {
        JwkRSA jwk = (JwkRSA) jwkKeys.forKeyId("RS_512").orElseThrow();
        RSAPrivateKey privateKey = (RSAPrivateKey) jwk.privateKey().orElseThrow();

        EncryptedJwt encryptedJwt = builder(signedJwt)
                .jwk(jwk)
                .algorithm(SupportedAlgorithm.RSA_OAEP_256)
                .encryption(SupportedEncryption.A256CBC_HS512)
                .build();

        JWEObject jweObject = JWEObject.parse(encryptedJwt.token());
        jweObject.decrypt(new RSADecrypter(privateKey));
        SignedJWT signedJWT = SignedJWT.parse(jweObject.getPayload().toString());

        assertThat(JsonParser.create(signedJWT.getPayload().toString()).readJsonObject(),
                   is(signedJwt.getJwt().payloadJsonObject()));
    }

    @Test
    void testHelidonPayloadToNimbus() throws ParseException, JOSEException {
        JwkRSA jwk = (JwkRSA) jwkKeys.forKeyId("RS_512").orElseThrow();
        RSAPrivateKey privateKey = (RSAPrivateKey) jwk.privateKey().orElseThrow();
        String payload = "{\"sub\":\"helidon-user\"}";

        EncryptedJwt encryptedJwt = payloadBuilder(payload.getBytes(StandardCharsets.UTF_8))
                .jwk(jwk)
                .algorithm(SupportedAlgorithm.RSA_OAEP_256)
                .encryption(SupportedEncryption.A256GCM)
                .build();

        JWEObject jweObject = JWEObject.parse(encryptedJwt.token());
        jweObject.decrypt(new RSADecrypter(privateKey));

        assertThat(jweObject.getHeader().getContentType(), is((String) null));
        assertThat(jweObject.getPayload().toString(), is(payload));
    }

}
