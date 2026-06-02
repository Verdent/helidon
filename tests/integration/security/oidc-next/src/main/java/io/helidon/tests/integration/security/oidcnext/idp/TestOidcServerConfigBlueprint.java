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

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.json.JsonValue;

@Prototype.Blueprint
interface TestOidcServerConfigBlueprint {
    @Option.Singular("client")
    Map<String, TestOidcClientConfig> clients();

    @Option.Singular("user")
    Map<String, TestOidcUserConfig> users();

    Optional<String> defaultAuthorizationUser();

    Optional<URI> issuer();

    @Option.Default({"openid"})
    @Option.Singular("defaultScope")
    List<String> defaultScopes();

    @Option.Singular("allowedScope")
    List<String> allowedScopes();

    @Option.DefaultBoolean(false)
    boolean browserLogin();

    @Option.Default("create()")
    TestOidcTokenDefaults tokenDefaults();

    @Option.Default("create()")
    TestOidcEndpointsConfig endpoints();

    @Option.Default("create()")
    TestOidcProviderMetadataConfig metadata();
}

@Prototype.Blueprint
interface TestOidcClientConfigBlueprint {
    @Option.Required
    String clientId();

    Optional<String> clientSecret();

    @Option.Singular("redirectUri")
    List<URI> redirectUris();
}

@Prototype.Blueprint
interface TestOidcUserConfigBlueprint {
    Optional<String> subject();

    Optional<String> password();

    @Option.Singular("claim")
    Map<String, JsonValue> claims();
}

@Prototype.Blueprint
interface TestOidcTokenDefaultsBlueprint {
    @Option.Default("create()")
    TestOidcTokenConfig accessToken();

    @Option.Default("create()")
    TestOidcTokenConfig idToken();

    @Option.Default("create()")
    TestOidcRefreshTokenConfig refreshToken();
}

@Prototype.Blueprint
interface TestOidcTokenConfigBlueprint {
    @Option.DefaultBoolean(false)
    boolean opaque();

    @Option.Default("PT1H")
    Duration expiresIn();

    @Option.Singular("claim")
    Map<String, JsonValue> claims();

    @Option.Singular("includeUserClaim")
    List<String> includeUserClaims();

    @Option.Singular("audience")
    List<String> audience();
}

@Prototype.Blueprint
interface TestOidcRefreshTokenConfigBlueprint {
    @Option.DefaultBoolean(false)
    boolean enabled();

    @Option.DefaultBoolean(false)
    boolean rotate();

    @Option.DefaultBoolean(false)
    boolean idTokenEnabled();
}

@Prototype.Blueprint
interface TestOidcEndpointsConfigBlueprint {
    Optional<TestOidcEndpointHandler<TestOidcEndpointContext>> metadata();

    Optional<TestOidcEndpointHandler<TestOidcEndpointContext>> authorization();

    Optional<TestOidcEndpointHandler<TestOidcTokenEndpointContext>> token();

    Optional<TestOidcEndpointHandler<TestOidcEndpointContext>> jwks();

    Optional<TestOidcEndpointHandler<TestOidcEndpointContext>> introspection();

    Optional<TestOidcEndpointHandler<TestOidcEndpointContext>> userinfo();

    Optional<TestOidcEndpointHandler<TestOidcEndpointContext>> logout();
}

@Prototype.Blueprint
interface TestOidcProviderMetadataConfigBlueprint {
    @Option.Singular("claim")
    Map<String, JsonValue> claims();
}
