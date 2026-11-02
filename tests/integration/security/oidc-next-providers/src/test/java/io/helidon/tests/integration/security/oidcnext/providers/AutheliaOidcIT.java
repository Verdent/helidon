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
    void nativeAccessTokenIsNotACompactJwt() throws Exception {
        String token = userTokens(IdpAdapter.ClientMode.BASIC).stringValue("access_token").orElseThrow();
        int segments = token.split("\\.", -1).length;
        // A compact JWS has three segments, and a compact JWE has five. This shape check
        // alone cannot prove opacity; native introspection in the shared contract tests usability.
        assertThat("Authelia token should not be a compact JWT", segments == 3 || segments == 5, is(false));
    }

    // OIDC Core 1.0 errata 2 §5.3.2: "If signed, the UserInfo Response MUST contain the Claims `iss` (issuer)
    // and `aud` (audience) as members." The shared helper first proves this OP omits both, then checks RP rejection.
    @Test
    void signedUserInfoWithoutMandatoryIssuerAndAudienceDoesNotCreateASession() throws Exception {
        assertNonconformingSignedUserInfoIsRejected();
    }

    // RFC 9126 §3: authorization parameters "MUST appear as claims of the JWT representing the authorization
    // request" when using PAR with a Request Object. The helper proves the RP is compliant before asserting
    // the known provider-specific rejection, not an RP defect.
    @Test
    void compliantParWithJarIsRejectedWithoutCreatingASession() throws Exception {
        assertCompliantParWithJarIsRejectedByTheProvider();
    }

    // Helidon local-session fallback policy for an OP 500 after revocation, not a mandated OAuth refresh response.
    @Test
    void serverErrorAfterRefreshRevocationDoesNotRenewTheUnexpiredSession() throws Exception {
        assertRefreshRevocationServerErrorDoesNotRenewTheSession();
    }
}
