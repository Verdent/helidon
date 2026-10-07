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

import java.util.List;
import java.util.Map;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.json.JsonValue;

/**
 * Typed authorization request parameters, including repeated occurrences.
 * Each list element is one parameter occurrence; a JSON array inside an element is one structured value.
 * This runtime request data is customized before core binding checks and transport serialization.
 */
@Prototype.Blueprint(decorator = OidcAuthorizationParametersDecorator.class)
interface OidcAuthorizationParametersBlueprint {
    /**
     * Parameter names and their semantic JSON values.
     * Strings retain their contents; other values use JSON serialization in query/form transport.
     * Repeated occurrences become arrays in a Request Object. Omit a name to omit the parameter.
     * Generic null values serialize as JSON null; nested null values are preserved.
     * The map and its occurrence lists are immutable after construction.
     *
     * @return parameters
     */
    @Option.Singular("parameter")
    @Option.Confidential
    Map<String, List<JsonValue>> parameters();
}
