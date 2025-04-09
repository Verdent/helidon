package io.helidon.json.tests;

import java.util.List;

import io.helidon.json.binding.Json;

@Json.Entity
public record SimpleRecord(@Json.Nullable String test, List<Integer> ints, List<Integer> ints2, int primitiveInt) {

    public void something() {

    }

}
