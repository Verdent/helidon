package io.helidon.jsonchema.tests;

import io.helidon.jsonschema.schema.Schema;

public class Main {

    public static void main(String[] args) {
        Schema schema = Schema.builder()
                .rootObject(builder -> builder.minProperties(5).maxProperties(1))
                .build();

        System.out.println(schema.generate());

        Schema parse = Schema.parse("""
                                            {
                                                "$schema": "https://json-schema.org/draft/2020-12/schema",
                                                "type": "object",
                                                "properties": {
                                                    "testInt": {
                                                        "title": "Test integer",
                                                        "description": "This integer is intended for a test",
                                                        "type": "integer",
                                                        "multipleOf": 2,
                                                        "minimum": 0,
                                                        "maximum": 4
                                                    },
                                                    "car": {
                                                        "title": "Test car override",
                                                        "description": "Car description override",
                                                        "type": "object",
                                                        "properties": {
                                                            "color": {
                                                                "description": "The color of my car",
                                                                "type": "string"
                                                            }
                                                        }
                                                    }
                                                },
                                                "required": [
                                                    "car"
                                                ]
                                            }
                                            """);
        System.out.println();
    }

}
