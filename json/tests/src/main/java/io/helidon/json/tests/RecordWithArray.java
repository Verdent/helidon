package io.helidon.json.tests;

import io.helidon.json.binding.Json;

@Json.Entity
public record RecordWithArray(Integer[] intArray) {
}
