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

import java.util.Optional;

final class OidcBearerTokenExtractionResult {
    private static final OidcBearerTokenExtractionResult EMPTY = new OidcBearerTokenExtractionResult(null, null);

    private final OidcBearerTokenEvidence evidence;
    private final String errorDescription;

    private OidcBearerTokenExtractionResult(OidcBearerTokenEvidence evidence, String errorDescription) {
        this.evidence = evidence;
        this.errorDescription = errorDescription;
    }

    static OidcBearerTokenExtractionResult empty() {
        return EMPTY;
    }

    static OidcBearerTokenExtractionResult evidence(OidcBearerTokenEvidence evidence) {
        return new OidcBearerTokenExtractionResult(evidence, null);
    }

    static OidcBearerTokenExtractionResult invalidRequest(String errorDescription) {
        return new OidcBearerTokenExtractionResult(null, errorDescription);
    }

    Optional<OidcBearerTokenEvidence> evidence() {
        return Optional.ofNullable(evidence);
    }

    boolean invalidRequest() {
        return errorDescription != null;
    }

    Optional<String> errorDescription() {
        return Optional.ofNullable(errorDescription);
    }
}
