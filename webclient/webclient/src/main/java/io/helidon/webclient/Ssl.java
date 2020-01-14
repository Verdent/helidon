/*
 * Copyright (c) 2020 Oracle and/or its affiliates. All rights reserved.
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
package io.helidon.webclient;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;

import io.helidon.common.pki.KeyConfig;
import io.helidon.config.Config;

import io.netty.handler.ssl.ClientAuth;

/**
 * Configuration of SSL requests.
 */
public class Ssl {

    private final boolean trustAll;
    private final boolean disableHostnameVerification;
    private final ClientAuth clientAuthentication;
    private final PrivateKey clientPrivateKey;
    private final List<X509Certificate> certificates;
    private final List<X509Certificate> clientCertificateChain;

    private Ssl(Builder builder) {
        this.trustAll = builder.trustAll;
        this.disableHostnameVerification = builder.disableHostnameVerification;
        this.clientAuthentication = builder.clientAuthentication;
        this.certificates = builder.certificates;
        this.clientPrivateKey = builder.clientPrivateKey;
        this.clientCertificateChain = builder.clientCertificateChain;
    }

    /**
     * Fluent API builder for new instances.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * If all server certificates should be trusted. Trust store is ignored.
     *
     * Default value is {@code false}.
     *
     * @return trust all certificates
     */
    public boolean trustAll() {
        return trustAll;
    }

    /**
     * If server hostname verification should be disabled.
     *
     * Default value is {@code false}.
     *
     * @return disable hostname verification
     */
    public boolean disableHostnameVerification() {
        return disableHostnameVerification;
    }

    /**
     * Client authentication strategy.
     *
     * Default value is {@link ClientAuth#NONE}.
     *
     * @return client authentication
     */
    public ClientAuth clientAuthentication() {
        return clientAuthentication;
    }

    /**
     * Trusted certificates.
     *
     * @return trusted certificates
     */
    public List<X509Certificate> certificates() {
        return certificates;
    }

    /**
     * Client private key for authentication.
     *
     * @return client private key
     */
    public PrivateKey clientPrivateKey() {
        return clientPrivateKey;
    }

    /**
     * Client certificate chain.
     *
     * @return client certificate chain
     */
    public List<X509Certificate> clientCertificateChain() {
        return clientCertificateChain;
    }

    /**
     * Fluent API builder for {@link Ssl} instance.
     */
    public static class Builder implements io.helidon.common.Builder<Ssl> {

        private boolean clientAuthenticationNotSet = true;
        private boolean trustAll = false;
        private boolean disableHostnameVerification = false;
        private ClientAuth clientAuthentication = ClientAuth.NONE;
        private PrivateKey clientPrivateKey;
        private List<X509Certificate> certificates = new ArrayList<>();
        private List<X509Certificate> clientCertificateChain = new ArrayList<>();
        private SSLContext sslContext;

        private Builder() {
        }

        /**
         * Sets if hostname verification should be disabled.
         *
         * @param disableHostnameVerification disabled verification
         * @return updated builder instance
         */
        public Builder disableHostnameVerification(boolean disableHostnameVerification) {
            this.disableHostnameVerification = disableHostnameVerification;
            return this;
        }

        /**
         * Sets if all certificates should be trusted to.
         *
         * @param trustAll trust all certificates
         * @return updated builder instance
         */
        public Builder trustAll(boolean trustAll) {
            this.trustAll = trustAll;
            return this;
        }

        public Builder certificateTrustStore(KeyConfig keyStore) {
            certificates = keyStore.certs();
            return null;
        }

        Builder clientAuthentication(String clientAuthentication) {
            return clientAuthentication(ClientAuth.valueOf(clientAuthentication));
        }

        public Builder clientAuthentication(ClientAuth clientAuthentication) {
            this.clientAuthentication = clientAuthentication;
            this.clientAuthenticationNotSet = false;
            return this;
        }

        public Builder clientKeyStore(KeyConfig keyConfig) {
            keyConfig.privateKey().ifPresent(privateKey -> clientPrivateKey = privateKey);
            clientCertificateChain = keyConfig.certChain();
            return this;
        }

        //TODO ssl zmenit jak se vytvari context pro netty
        public Builder sslContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        public Builder config(Config config) {
            Config serverConfig = config.get("server");
            serverConfig.get("disable-hostname-verification").asBoolean().ifPresent(this::disableHostnameVerification);
            serverConfig.get("trust-all").asBoolean().ifPresent(this::trustAll);
            serverConfig.get("truststore").as(KeyConfig::create).ifPresent(this::certificateTrustStore);

            Config clientConfig = config.get("client");
            clientConfig.get("client-auth").asString().ifPresent(this::clientAuthentication);
            clientConfig.get("keystore").as(KeyConfig::create).ifPresent(this::clientKeyStore);
            return this;
        }

        @Override
        public Ssl build() {
            if (clientAuthenticationNotSet && clientPrivateKey != null) {
                clientAuthentication = ClientAuth.OPTIONAL;
            }
            return new Ssl(this);
        }
    }
}
