package io.helidon.json.tests;

import io.helidon.json.binding.Json;

@Json.Entity
public class ClassUsingClassWithGenerics {

    public ClassWithGenerics<Integer> test;

}
