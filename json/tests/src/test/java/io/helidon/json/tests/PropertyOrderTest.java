package io.helidon.json.tests;

import io.helidon.json.binding.Json;
import io.helidon.json.binding.JsonBinding;
import io.helidon.json.binding.Order;
import io.helidon.service.registry.Services;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class PropertyOrderTest {

    private static final JsonBinding HELIDON = Services.get(JsonBinding.class);

    @Test
    public void testDefaultPropertyOrder() {
        DefaultPropertyOrderRecord testRecord = new DefaultPropertyOrderRecord("Full value", "first name", "last name");
        assertThat(HELIDON.serialize(testRecord),
                   is("{\"fullName\":\"Full value\",\"firstName\":\"first name\",\"lastName\":\"last name\"}"));
    }

    @Test
    public void testAnyPropertyOrder() {
        AnyOrderRecord testRecord = new AnyOrderRecord("Full value", "first name", "last name");
        assertThat(HELIDON.serialize(testRecord),
                   is("{\"fullName\":\"Full value\",\"firstName\":\"first name\",\"lastName\":\"last name\"}"));
    }

    @Test
    public void testAlphabeticalPropertyOrder() {
        AlphabeticalOrderRecord testRecord = new AlphabeticalOrderRecord("Full value", "first name", "last name");
        assertThat(HELIDON.serialize(testRecord),
                   is("{\"firstName\":\"first name\",\"fullName\":\"Full value\",\"lastName\":\"last name\"}"));
    }

    @Test
    public void testReversePropertyOrder() {
        ReverseOrderRecord testRecord = new ReverseOrderRecord("Full value", "first name", "last name");
        assertThat(HELIDON.serialize(testRecord),
                   is("{\"lastName\":\"last name\",\"fullName\":\"Full value\",\"firstName\":\"first name\"}"));
    }

    @Json.Entity
    record DefaultPropertyOrderRecord(String fullName, String firstName, String lastName) {
    }

    @Json.Entity
    @Json.PropertyOrder(Order.UNDEFINED)
    record AnyOrderRecord(String fullName, String firstName, String lastName) {
    }

    @Json.Entity
    @Json.PropertyOrder(Order.ALPHABETICAL)
    record AlphabeticalOrderRecord(String fullName, String firstName, String lastName) {
    }

    @Json.Entity
    @Json.PropertyOrder(Order.REVERSE_ALPHABETICAL)
    record ReverseOrderRecord(String fullName, String firstName, String lastName) {
    }

}
