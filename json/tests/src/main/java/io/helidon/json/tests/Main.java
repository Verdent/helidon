package io.helidon.json.tests;

import java.util.List;

import io.helidon.common.GenericType;
import io.helidon.json.binding.JsonBinding;

public class Main {

    public static void main(String[] args) {

        GenericType<List<String>> genericType = new GenericType<>() { };
//        SimpleClass deserialize = JsonBinding.deserialize("{\"name\":\"value\"}", SimpleClass.class);
        SimpleRecord record = JsonBinding.deserialize("{\"ints\":[1,2,3]}", SimpleRecord.class);
        System.out.println();

        //        SimpleRecord record = new SimpleRecord("testValue", List.of(1, 2, 3), 1);
    }

}
