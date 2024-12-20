package io.helidon.json.tests;

import java.util.List;

import io.helidon.json.binding.JsonBinding;

public class Main {

    public static void main(String[] args) {

        JsonBinding build = JsonBinding.builder().build();
        System.out.println();

        //        SimpleRecord record = new SimpleRecord("testValue", List.of(1, 2, 3), 1);
    }

}
