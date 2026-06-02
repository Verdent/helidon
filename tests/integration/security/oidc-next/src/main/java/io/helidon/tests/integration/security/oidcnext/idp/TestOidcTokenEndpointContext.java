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

package io.helidon.tests.integration.security.oidcnext.idp;

/**
 * Token endpoint override context.
 */
public interface TestOidcTokenEndpointContext extends TestOidcEndpointContext {
    /**
     * Validate the current token request and create the default token response model without sending it.
     *
     * @return token response
     */
    TestOidcTokenResponse issueTokens();

    /**
     * Send a successful token endpoint response using the default token response headers.
     *
     * @param tokenResponse token response to send
     */
    void send(TestOidcTokenResponse tokenResponse);
}
