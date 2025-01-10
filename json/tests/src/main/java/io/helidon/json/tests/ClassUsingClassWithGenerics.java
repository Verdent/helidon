package io.helidon.json.tests;

import io.helidon.json.binding.Json;

@Json.AsJson
public class ClassUsingClassWithGenerics {

    public ClassWithGenerics<Integer> test;

}
