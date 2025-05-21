package io.helidon.json.binding;

import java.util.Optional;

import io.helidon.builder.api.Prototype;

@Prototype.Blueprint
interface FormatterBlueprint {

    Optional<String> format();

    Optional<String> locale();

}
