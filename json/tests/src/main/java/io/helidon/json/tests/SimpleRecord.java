package io.helidon.json.tests;

import java.util.List;

import io.helidon.json.binding.Json;

@Json.AsJson
public record SimpleRecord(String test, List<Integer> ints, int primitiveInt) {

    public void something() {

    }

}
