package io.helidon.json.schema.tests;

import io.helidon.json.schema.JsonSchema;

@JsonSchema.Schema
@JsonSchema.Description("My super car")
public record Car(@JsonSchema.Description("The color of my car") String color) {
}
