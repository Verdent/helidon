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

final class TestKeys {
    static final String KEY_ID = "ec-secret-001";

    static final String PRIVATE_SIGNING_JWK = """
            {
              "keys": [
                {
                  "kty": "EC",
                  "crv": "P-256",
                  "kid": "ec-secret-001",
                  "use": "sig",
                  "x": "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
                  "y": "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
                  "d": "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk",
                  "alg": "ES256"
                }
              ]
            }
            """;

    static final String PUBLIC_SPIFFE_BUNDLE = """
            {
              "keys": [
                {
                  "kty": "EC",
                  "crv": "P-256",
                  "kid": "ec-secret-001",
                  "use": "jwt-svid",
                  "x": "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
                  "y": "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
                  "alg": "ES256"
                }
              ]
            }
            """;

    private TestKeys() {
    }
}
