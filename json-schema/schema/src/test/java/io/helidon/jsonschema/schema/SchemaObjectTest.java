package io.helidon.jsonschema.schema;

import org.junit.jupiter.api.Test;

public class SchemaObjectTest {

    @Test
    public void testSchemaObject() {
        Schema schema = Schema.builder()
                .rootObject(builder -> builder
                                  .putIntegerProperty("cislo", builder2 -> builder2.title("HUSTY CISLOOO")
                                          .description("Moje nejvic husty cislo")
                                          .required(true))
                                  .putStringProperty("text", builder2 -> builder2.title("nejaky text")))
                .build();

        String generate = schema.generate();
        System.out.println(generate);


        schema = Schema.builder()
                .rootInteger(builder -> builder.multipleOf(4))
                .build();

        generate = schema.generate();
        System.out.println(generate);
    }

}
