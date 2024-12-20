package io.helidon.json.binding;

import java.util.Map;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

@Prototype.Blueprint
@Prototype.Configured
//Prototype.RegistrySupport
interface JsonBindingConfigBlueprint extends Prototype.Factory<JsonBinding> {

    /**
     * Map of the registered serializers.
     *
     * @return registered serializers
     */
    @Option.Singular
    //@Option.RegistryService
    Map<Class<?>, JsonSerializer<?>> serializers();


//    List<TypedJsonSerializer>
    /**
     * Map of the registered deserializers.
     *
     * @return registered deserializers
     */
    @Option.Singular
    Map<Class<?>, JsonDeserializer<?>> deserializers();

}
