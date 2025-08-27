package io.helidon.http.media.helison;

import io.helidon.common.Weighted;
import io.helidon.common.config.Config;
import io.helidon.http.media.MediaSupport;
import io.helidon.http.media.spi.MediaSupportProvider;

public class HelisonMediaSupportProvider implements MediaSupportProvider, Weighted {
    @Override
    public String configKey() {
        return "helison";
    }

    @Override
    public MediaSupport create(Config config, String name) {
        return HelisonSupport.create(config, name);
    }

    @Override
    public double weight() {
        // very low weight, as this covers all, but higher than Jackson
        return 20;
    }
}
