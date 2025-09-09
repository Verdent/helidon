package io.helidon.jsonschema.schema;

import java.util.Optional;

import io.helidon.builder.api.Option;
import io.helidon.builder.api.Prototype;

@Prototype.Blueprint(decorator = SchemaDecorator.class, createEmptyPublic = false)
@Prototype.CustomMethods(SchemaCustomMethods.class)
interface SchemaBlueprint {

    Optional<String> id();

    @Option.Access("")
    SchemaItem root();

    Optional<SchemaObject> rootObject();

    Optional<SchemaArray> rootArray();

    Optional<SchemaNumber> rootNumber();

    Optional<SchemaInteger> rootInteger();

    Optional<SchemaString> rootString();

    Optional<SchemaBoolean> rootBoolean();

    Optional<SchemaNull> rootNull();

}
