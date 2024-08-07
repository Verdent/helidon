package io.helidon.json.codegen;

import java.util.Optional;

import io.helidon.builder.api.Prototype;
import io.helidon.common.types.TypeName;

@Prototype.Blueprint(isPublic = false)
interface JsonPropertyBlueprint {

    Optional<String> fieldName();

    Optional<String> getterName();

    Optional<String> setterName();

    Optional<String> deserializationName();

    Optional<String> serializationName();

    Optional<TypeName> deserializationType();

    Optional<TypeName> serializationType();

    Optional<TypeName> deserializer();

    Optional<TypeName> serializer();

    boolean propertyIgnored();

    boolean getterIgnored();

    boolean setterIgnored();

    boolean usedInCreator();

    boolean directFieldAccess();

}
