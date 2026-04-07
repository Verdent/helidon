/*
 * Copyright (c) 2024, 2026 Oracle and/or its affiliates.
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

package io.helidon.common.tls;

import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLParameters;

import io.helidon.config.Config;
import io.helidon.config.MapConfigSource;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class TlsTest {
    @Test
    public void testTlsEquals() {
        SSLParameters first = new SSLParameters();
        SSLParameters second = new SSLParameters();

        assertThat(Tls.equals(first, second), is(true));

        AlgorithmConstraints constraints = new AlgorithmConstraints() {
            @Override
            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) {
                return false;
            }

            @Override
            public boolean permits(Set<CryptoPrimitive> primitives, Key key) {
                return false;
            }

            @Override
            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
                return false;
            }
        };

        first.setAlgorithmConstraints(constraints);
        second.setAlgorithmConstraints(constraints);

        assertThat(Tls.equals(first, second), is(true));

        first.setServerNames(List.of());
        second.setServerNames(List.of());

        assertThat(Tls.equals(first, second), is(true));

        first.setSNIMatchers(List.of());
        second.setSNIMatchers(List.of());
    }

    @Test
    void disabledTlsDoesNotResolveConfiguredManager() {
        Tls tls = Tls.create(config(false));

        assertThat(tls.enabled(), is(false));
    }

    @Test
    void enabledTlsStillValidatesConfiguredManager() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                                                          () -> Tls.create(config(true)));

        assertThat(exception.getMessage(), is(FailingTlsManagerProvider.FAILURE_MESSAGE));
    }

    private static Config config(boolean enabled) {
        return Config.just(MapConfigSource.create(Map.of(
                "server.tls.enabled", Boolean.toString(enabled),
                "server.tls.manager.failing.name", "failing-manager"
        ))).get("server.tls");
    }
}
