/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
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
package io.helidon.webclient.ssl;

import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/**
 * {@link javax.net.ssl.HostnameVerifier} that does no hostname verification.
 * Use with care, as this effectively disables checking that the certificate
 * belongs to the server we are requesting, allowing man-in-the-middle attacks.
 */
public class NoneHostnameVerifier implements HostnameVerifier {
    private static final Logger LOGGER = Logger.getLogger(NoneHostnameVerifier.class.getName());

    @Override
    public boolean verify(String hostName, SSLSession sslSession) {
        LOGGER.finest(() -> "Allowing access over SSL to " + hostName);
        return true;
    }
}
