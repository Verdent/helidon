package io.helidon.jsonchema.tests;

import java.util.List;
import java.util.Set;

import io.helidon.jsonschema.schema.JsonSchema;

@JsonSchema.Schema
public class ObjectWithArray {

    private String[] array;

    private List<String> list;

    @JsonSchema.Description("The list of my favorite cars")
    private Set<Car> cars;

}
