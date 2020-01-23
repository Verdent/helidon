package io.helidon.webclient;

import io.helidon.config.Config;
import io.helidon.config.ConfigSources;

import io.netty.handler.ssl.ClientAuth;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * TODO Javadoc
 */
public class SslTest {

    @Test
    public void sslDefaults() {
        Ssl ssl = Ssl.builder().build();

        assertThat(ssl.disableHostnameVerification(), is(false));
        assertThat(ssl.trustAll(), is(false));
        assertThat(ssl.clientAuthentication(), is(ClientAuth.NONE));
    }

    @Test
    public void sslFromConfig() {
        Config config = Config.builder()
                .disableSystemPropertiesSource()
                .disableEnvironmentVariablesSource()
                .sources(ConfigSources.classpath("ssl-config.yaml"))
                .build();
        Ssl ssl = Ssl.builder().config(config.get("ssl")).build();

        assertThat(ssl.disableHostnameVerification(), is(true));
        assertThat(ssl.trustAll(), is(true));
        assertThat(ssl.clientAuthentication(), is(ClientAuth.REQUIRE));
    }

}
