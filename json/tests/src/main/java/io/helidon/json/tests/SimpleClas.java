package io.helidon.json.tests;

import io.helidon.json.binding.Json;

@Json.AsJson
public class SimpleClas {

    public String name;

    public String getName() {
        return name;
    }

    @Json.Property("something")
    public String get() {
        return name;
    }

}
