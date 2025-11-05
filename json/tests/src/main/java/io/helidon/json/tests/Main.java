package io.helidon.json.tests;

import java.util.List;

import io.helidon.json.binding.JsonBinding;

public class Main {

    public static void main(String[] args) {
        //        SimpleClass deserialize = JsonBinding.deserialize("{\"name\":\"value\"}", SimpleClass.class);
        //        SimpleRecord record = JsonBinding.deserialize("{\"ints\":[1,2,3]}", SimpleRecord.class);
        //        System.out.println();

        //        SimpleRecord record = new SimpleRecord("testValue", List.of(1, 2, 3), 1);

        //        ClassUsingClassWithGenerics deserialize = JsonBinding.deserialize("{\"test\":{\"collection\":[1,2,3]}}",
        //                                                                          ClassUsingClassWithGenerics.class);
        //
        //        System.out.println();

        //        RecordWithArray deserialize = JsonBinding.deserialize("""
        //                                                                      {
        //                                                                      "intArray":[1,2,3],
        //                                                                      "intArray2":[[1,2,3], [4,5]],
        //                                                                      "intArray3":[[[1,2,3], [4,5]], [[6], [7,8,9,
        //                                                                      0]], [[1,2,3,4,5,6], [7]]],
        //                                                                      "strArray":["Hi", "I", "am","String", "array"],
        //                                                                      "simpleClassArray":[{"name":"custom name"}]
        //                                                                      }
        //                                                                      """, RecordWithArray.class);
        //        System.out.println();

//        SimpleRecord record = new SimpleRecord(null, null, List.of(1, 2), 4321);
//        String json = JsonBinding.serialize(record);
////        JsonBinding jsonBinding = JsonBinding.builder()
////                .writeNulls(true)
////                .build();
////        json = jsonBinding.toJson(record);
//
//        System.out.println(json);

//        JsonBinding binding = JsonBinding.create();
//        String test = """
//                {
//                    "map" : {
//                        "myKey1" : "192￡",
//                        "myKey2" : "myValue2"
//                    }
//                }
//                """;
//        ObjectWithMap map = binding.deserialize(test, ObjectWithMap.class);
//        String serialized = binding.serialize(map);
//        ObjectWithMap map2 = binding.deserialize(test, ObjectWithMap.class);
//        System.out.println();

        JsonBinding binding = JsonBinding.create();

        binding.deserialize("192￡", int.class);



    }

}
