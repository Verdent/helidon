package io.helidon.json.tests;

import io.helidon.json.binding.Json;

@Json.AsJson
public class GenericChild extends GenericParent<String> {
}
