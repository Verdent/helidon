package io.helidon.json.schema.tests;

import io.helidon.json.schema.JsonSchema;

@JsonSchema.Schema
public class DemoSchema {

    @JsonSchema.Description("My id")
    @JsonSchema.Required
    private String id;

    @JsonSchema.Description("My car")
    private Car car;

    @JsonSchema.Integer.Minimum(5)
    private int value;

    public void id(String id) {
        this.id = id;
    }

}
