package io.helidon.jsonschema.tests;

import io.helidon.jsonchema.tests.Car;
import io.helidon.jsonschema.schema.Schema;

import org.junit.jupiter.api.Test;

public class SchemaServiceRegistryTest {

    @Test
    public void testSchemaFromServiceRegistry() {
        Schema schema = Schema.get(Car.class);

    }

}
