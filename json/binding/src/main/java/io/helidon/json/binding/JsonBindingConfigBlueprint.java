package io.helidon.json.binding;

import java.util.Map;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

@Prototype.Blueprint
@Prototype.Configured
interface JsonBindingConfigBlueprint {

    /**
     * Map of the registered serializers.
     *
     * @return registered serializers
     */
    @Option.Singular
    Map<Class<?>, JsonSerializer<?>> serializers();

    /**
     * Map of the registered deserializers.
     *
     * @return registered deserializers
     */
    @Option.Singular
    Map<Class<?>, JsonDeserializer<?>> deserializers();

}
