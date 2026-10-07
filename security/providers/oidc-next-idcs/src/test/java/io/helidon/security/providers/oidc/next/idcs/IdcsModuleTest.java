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

package io.helidon.security.providers.oidc.next.idcs;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.spi.ToolProvider;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

class IdcsModuleTest {
    @Test
    void namedConsumerCanCompileAndRunUsingOnlyTheIdcsModule(@TempDir Path directory) throws Exception {
        Path descriptor = directory.resolve("module-info.java");
        Files.writeString(descriptor, """
                module idcs.consumer {
                    requires io.helidon.security.providers.oidc.next.idcs;
                }
                """);
        Path consumer = directory.resolve("Consumer.java");
        Files.writeString(consumer, """
                package consumer;

                import java.net.URI;
                import java.util.Map;

                import io.helidon.common.Builder;
                import io.helidon.config.Config;
                import io.helidon.config.ConfigSources;
                import io.helidon.security.SecurityEnvironment;
                import io.helidon.security.providers.oidc.next.OidcAuthorizationParameters;
                import io.helidon.security.providers.oidc.next.OidcTenantConfig;
                import io.helidon.security.providers.oidc.next.idcs.IdcsTenantAdapter;
                import io.helidon.security.providers.oidc.next.idcs.IdcsTenantAdapterProvider;
                import io.helidon.security.providers.oidc.next.spi.OidcTenantAdapter;
                import io.helidon.security.providers.oidc.next.spi.OidcTenantAdapterProvider;
                import io.helidon.webclient.api.WebClient;

                public final class Consumer {
                    public static void main(String[] args) {
                        URI domain = URI.create("https://idcs.example");
                        Builder<IdcsTenantAdapter.Builder, IdcsTenantAdapter> builder =
                                IdcsTenantAdapter.builder().domainUri(domain);
                        OidcTenantAdapter adapter = builder.build();
                        OidcTenantConfig tenant = OidcTenantConfig.builder().adapter(adapter).buildPrototype();
                        Config config = Config.builder()
                                .sources(ConfigSources.create(Map.of("domain-uri", domain.toString())))
                                .build();
                        OidcTenantAdapterProvider factory = new IdcsTenantAdapterProvider();
                        OidcTenantAdapter configured = factory.create(config, "consumer");
                        var defaults = configured.jwtAccessTokenDefaults().orElseThrow();
                        if (!defaults.allowedTypes().contains("at+jwt")) {
                            throw new AssertionError("IDCS access-token defaults are unavailable");
                        }
                        OidcAuthorizationParameters parameters = OidcAuthorizationParameters.create();
                        if (adapter.authorizationRequest(tenant, "default", SecurityEnvironment.create(), parameters)
                                != parameters) {
                            throw new AssertionError("Inherited authorization hook did not preserve the parameters");
                        }
                        WebClient client = WebClient.create();
                        try {
                            String token = adapter.jwkSetAccessToken(tenant, tenant.endpoints().jwksUri().orElseThrow(),
                                    client, _ -> "consumer-token").orElseThrow();
                            if (!token.equals("consumer-token")) {
                                throw new AssertionError("IDCS credential hook did not return the acquired token");
                            }
                        } finally {
                            client.closeResource();
                        }
                        System.out.println("IDCS module consumer OK");
                    }
                }
                """);
        Path classes = Files.createDirectory(directory.resolve("classes"));
        String modulePath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        ToolProvider compiler = ToolProvider.findFirst("javac")
                .orElseThrow(() -> new IllegalStateException("The module test requires the javac tool"));
        StringWriter diagnostics = new StringWriter();
        try (PrintWriter output = new PrintWriter(diagnostics)) {
            int exitCode = compiler.run(output, output, "-proc:none", "--module-path", modulePath,
                                        "-d", classes.toString(), descriptor.toString(), consumer.toString());
            output.flush();
            assertThat(diagnostics.toString(), exitCode, is(0));
        }
        Path log = directory.resolve("consumer.log");
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                                             "--module-path", classes + File.pathSeparator + modulePath,
                                             "--module", "idcs.consumer/consumer.Consumer")
                .redirectErrorStream(true)
                .redirectOutput(log.toFile())
                .start();
        try {
            process.getOutputStream().close();
            assertThat("Named module consumer finished", process.waitFor(30, TimeUnit.SECONDS), is(true));
            String output = Files.readString(log);
            assertThat(output, process.exitValue(), is(0));
            assertThat(output, containsString("IDCS module consumer OK"));
        } finally {
            process.destroyForcibly();
        }
    }
}
