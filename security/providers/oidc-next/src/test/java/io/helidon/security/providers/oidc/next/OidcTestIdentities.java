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

import java.nio.charset.StandardCharsets;
import java.util.Base64;

final class OidcTestIdentities {
    private OidcTestIdentities() {
    }

    static String issuerSubject(String issuer, String subject) {
        return "oidc-sub:" + encode(issuer) + "." + encode(subject);
    }

    static String issuerClaim(String issuer, String path, String value) {
        return "oidc-claim:" + encode(issuer) + "." + encode(path) + "." + encode(value);
    }

    static String namespaceClaim(String namespace, String path, String value) {
        return "oidc-namespace:" + encode(namespace) + "." + encode(path) + "." + encode(value);
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
