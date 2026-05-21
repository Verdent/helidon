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

import io.helidon.security.jwt.Jwt;
import io.helidon.security.jwt.SignedJwt;

final class OidcValidatedJwt implements OidcValidatedAccessToken {
    private final String rawToken;
    private final SignedJwt signedJwt;
    private final Jwt jwt;

    private OidcValidatedJwt(String rawToken, SignedJwt signedJwt, Jwt jwt) {
        this.rawToken = rawToken;
        this.signedJwt = signedJwt;
        this.jwt = jwt;
    }

    static OidcValidatedJwt create(String rawToken, SignedJwt signedJwt, Jwt jwt) {
        return new OidcValidatedJwt(rawToken, signedJwt, jwt);
    }

    @Override
    public String rawToken() {
        return rawToken;
    }

    SignedJwt signedJwt() {
        return signedJwt;
    }

    Jwt jwt() {
        return jwt;
    }
}
