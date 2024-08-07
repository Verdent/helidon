package io.helidon.json.tests;

import io.helidon.json.binding.Json;

@Json.AsJson
public record SimpleRecord(String test) {

    public void something() {

    }

}
