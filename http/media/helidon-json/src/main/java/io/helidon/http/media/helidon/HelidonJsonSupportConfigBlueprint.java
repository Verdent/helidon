package io.helidon.http.media.helidon;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;
import io.helidon.http.media.spi.MediaSupportProvider;
import io.helidon.json.binding.JsonBinding;

@Prototype.Configured(value = "helidon-json", root = false)
@Prototype.Provides(MediaSupportProvider.class)
@Prototype.Blueprint(decorator = HelidonJsonSupport.Decorator.class)
interface HelidonJsonSupportConfigBlueprint extends Prototype.Factory<HelidonJsonSupport> {

    /**
     * Name of the support. Default value is {@code helidon-json}.
     *
     * @return name of the support
     */
    @Option.Default("helidon-json")
    @Option.Configured
    String name();

    JsonBinding jsonBinding();

}
