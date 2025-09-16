package io.helidon.json.schema.tests;

import io.helidon.json.schema.tests.Car;
import io.helidon.json.schema.Schema;

import org.junit.jupiter.api.Test;

public class SchemaServiceRegistryTest {

    @Test
    public void testSchemaFromServiceRegistry() {
        Schema schema = Schema.get(Car.class);

    }

}
