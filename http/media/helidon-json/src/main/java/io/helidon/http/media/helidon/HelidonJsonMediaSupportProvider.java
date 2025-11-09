package io.helidon.http.media.helidon;

import io.helidon.common.Weighted;
import io.helidon.common.config.Config;
import io.helidon.http.media.MediaSupport;
import io.helidon.http.media.spi.MediaSupportProvider;

public class HelidonJsonMediaSupportProvider implements MediaSupportProvider, Weighted {
    @Override
    public String configKey() {
        return "helidon-json";
    }

    @Override
    public MediaSupport create(Config config, String name) {
        return HelidonJsonSupport.create(config, name);
    }

    @Override
    public double weight() {
        // very low weight, as this covers all, but higher than Jackson
        return 20;
    }
}
