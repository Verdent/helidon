package io.helidon.http.media.helison;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.http.media.spi.MediaSupportProvider;
import io.helidon.json.binding.JsonBinding;

@Prototype.Configured(value = "helison", root = false)
@Prototype.Provides(MediaSupportProvider.class)
@Prototype.Blueprint
interface HelisonSupportConfigBlueprint extends Prototype.Factory<HelisonSupport> {

    /**
     * Name of the support. Default value is {@code helison}.
     *
     * @return name of the support
     */
    @Option.Default("helison")
    @Option.Configured
    String name();

    JsonBinding jsonBinding();

}
