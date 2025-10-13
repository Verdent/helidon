package io.helidon.json.tests;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import io.helidon.json.binding.JsonBinding;

public class Main4 {

    public static void main(String[] args) {
        ByteArrayInputStream bais = new ByteArrayInputStream("{\"name\":\"value\"}".getBytes(StandardCharsets.UTF_8));

        SimpleClass deserialize = JsonBinding.deserialize(bais, SimpleClass.class);

        System.out.println(deserialize);

    }

}
