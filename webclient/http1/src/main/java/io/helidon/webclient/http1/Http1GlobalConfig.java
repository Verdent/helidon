package io.helidon.webclient.http1;

import io.helidon.common.config.Config;
import io.helidon.common.config.GlobalConfig;

class Http1GlobalConfig {

    static final Http1ClientConfig GLOBAL_CLIENT_CONFIG;

    static {
        Config config = GlobalConfig.config();
        GLOBAL_CLIENT_CONFIG = Http1ClientConfig.builder().config(config.get("client")).buildPrototype();
    }

}
