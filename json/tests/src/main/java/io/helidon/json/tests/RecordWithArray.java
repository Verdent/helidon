package io.helidon.json.tests;

import io.helidon.json.binding.Json;

@Json.Entity
public record RecordWithArray(Integer[] intArray,
                              Integer[][] intArray2,
                              Integer[][][] intArray3,
                              String[] strArray,
                              SimpleClass[] simpleClassArray) {
}
