package io.helidon.json.binding;

import java.util.Optional;

import io.helidon.builder.api.Prototype;

@Prototype.Blueprint
interface JsonContextBlueprint {

    Optional<Formatter> dateFormat();

    Optional<Formatter> numberFormat();

}
