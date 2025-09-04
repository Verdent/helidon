package io.helidon.jsonchema.tests;

import io.helidon.jsonschema.schema.JsonSchema;

@JsonSchema.Description("My super car")
public record Car(@JsonSchema.Description("The color of my car") String color) {
}
