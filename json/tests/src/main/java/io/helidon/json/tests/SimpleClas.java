package io.helidon.json.tests;

import io.helidon.json.binding.Json;

@Json.AsJson
public class SimpleClas {

    public String name;

    public String getName() {
        return name;
    }

}
