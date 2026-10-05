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

package io.helidon.tests.integration.security.oidcnext.providers;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class AutheliaOidcIT extends OidcProviderContract {
    @Override
    IdpAdapter createAdapter() {
        return new AutheliaAdapter();
    }

    @Test
    void nativeAccessTokenIsOpaque() throws Exception {
        String token = userTokens(IdpAdapter.ClientMode.BASIC).stringValue("access_token").orElseThrow();
        int segments = token.split("\\.", -1).length;
        // A compact JWS has three segments, and a compact JWE has five.
        assertThat("Authelia must issue an opaque access token", segments == 3 || segments == 5, is(false));
    }

    @Test
    void signedUserInfoWithoutMandatoryIssuerAndAudienceDoesNotCreateASession() throws Exception {
        assertNonconformingSignedUserInfoIsRejected();
    }

    @Test
    void compliantParWithJarIsRejectedWithoutCreatingASession() throws Exception {
        assertCompliantParWithJarIsRejectedByTheProvider();
    }

    @Test
    void serverErrorAfterRefreshRevocationDoesNotRenewTheUnexpiredSession() throws Exception {
        assertRefreshRevocationServerErrorDoesNotRenewTheSession();
    }
}
