import io.helidon.common.features.api.Features;
import io.helidon.common.features.api.HelidonFlavor;

@Features.Name("Helidon JSON")
@Features.Description("Helidon JSON media support")
@Features.Flavor(HelidonFlavor.SE)
@Features.Path({"Media", "HelidonJSON"})
module helidon.http.media.json {
    requires io.helidon.builder.api;
    requires io.helidon.common.config;
    requires io.helidon.http.media;
    requires io.helidon.json.binding;
    requires io.helidon.common.media.type;
    requires io.helidon.http;

    requires static io.helidon.common.features.api;

    exports io.helidon.http.media.json;

    provides io.helidon.http.media.spi.MediaSupportProvider
            with io.helidon.http.media.json.HelidonJsonMediaSupportProvider;
}