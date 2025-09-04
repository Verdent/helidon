package io.helidon.jsonchema.tests;

import io.helidon.jsonschema.schema.Schema;

public class Main {

    public static void main(String[] args) {
        Schema schema = Schema.builder()
                .rootObject(builder -> builder.minProperties(5).maxProperties(1))
                .build();

        schema.rootObject();



//        Schema.create();
//        """
//                {
//                    type:object
//                }
//                """

        System.out.println(schema.generate());
    }

}
