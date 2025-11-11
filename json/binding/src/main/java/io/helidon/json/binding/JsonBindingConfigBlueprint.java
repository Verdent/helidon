package io.helidon.json.binding;

import java.util.List;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

@Prototype.Blueprint
@Prototype.Configured
@Prototype.RegistrySupport
@Prototype.CustomMethods(JsonBindingConfigCustomMethods.class)
interface JsonBindingConfigBlueprint extends Prototype.Factory<JsonBinding> {

    /**
     * Registered type serializers.
     *
     * @return registered serializers
     */
    @Option.Singular
    @Option.RegistryService
    List<JsonSerializer<?>> serializers();

    /**
     * Registered type deserializers.
     *
     * @return registered deserializers
     */
    @Option.Singular
    @Option.RegistryService
    List<JsonDeserializer<?>> deserializers();

    /**
     * Registered generic type binding factories.
     *
     * @return registered binding factories
     */
    @Option.Singular
    @Option.RegistryService
    List<JsonBindingFactory<?>> bindingFactories();

}
