package io.helidon.http.media.helison;

import java.util.function.Consumer;

import io.helidon.builder.api.RuntimeType;
import io.helidon.common.config.Config;
import io.helidon.http.media.MediaSupport;

@RuntimeType.PrototypedBy(HelisonSupportConfig.class)
public class HelisonSupport implements MediaSupport, RuntimeType.Api<HelisonSupportConfig> {

    private final String name;
    private final HelisonSupportConfig supportConfig;

    private HelisonSupport(HelisonSupportConfig supportConfig) {
        this.name = supportConfig.name();
        this.supportConfig = supportConfig;
    }

    public static MediaSupport create(Config config, String name) {
        return builder()
                .name(name)
                .config(config)
                .build();
    }

    public static HelisonSupport create(HelisonSupportConfig config) {
        return new HelisonSupport(config);
    }

    public static HelisonSupport create(Consumer<HelisonSupportConfig.Builder> consumer) {
        return builder().update(consumer).build();
    }

    public static HelisonSupportConfig.Builder builder() {
        return HelisonSupportConfig.builder();
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String type() {
        return "helison";
    }

    @Override
    public HelisonSupportConfig prototype() {
        return supportConfig;
    }
}
