package io.helidon.json.tests;

import java.util.Map;

import io.helidon.json.binding.Json;

@Json.Entity
public class ObjectWithMap {

    private Map<String, String> map;

    public Map<String, String> getMap() {
        return map;
    }

    public void setMap(Map<String, String> map) {
        this.map = map;
    }
}
