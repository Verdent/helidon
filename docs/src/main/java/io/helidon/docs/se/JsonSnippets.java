/*
 * Copyright (c) 2025 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.helidon.docs.se;

import java.util.List;
import java.util.Optional;

import io.helidon.json.JsonArray;
import io.helidon.json.JsonBoolean;
import io.helidon.json.JsonNull;
import io.helidon.json.JsonNumber;
import io.helidon.json.JsonObject;
import io.helidon.json.JsonParser;
import io.helidon.json.JsonString;
import io.helidon.json.Generator;
import io.helidon.json.binding.JsonBinding;
import io.helidon.json.binding.JsonConverter;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.common.GenericType;

@SuppressWarnings("ALL")
class JsonSnippets {

    void snippet_1() {
        // tag::snippet_1[]
        JsonBinding binding = JsonBinding.create();

        // Deserialize JSON string to object
        Person person = binding.deserialize("{\"name\":\"John\",\"age\":30}", Person.class);

        // Serialize object to JSON string
        String json = binding.serialize(person);
        // end::snippet_1[]
    }

    // tag::snippet_2[]
    @Json.Entity
    public class Person {
        private String name;
        private int age;

        // getters and setters
    }
    // end::snippet_2[]

    void snippet_3() {
        // tag::snippet_3[]
        JsonParser parser = JsonParser.create("{\"name\":\"John\",\"age\":30}");

        JsonObject object = parser.readJsonObject();

        String name = object.stringValue("name"); // "John"
        int age = object.intValue("age"); // 30
        // end::snippet_3[]
    }

    void snippet_4() {
        // tag::snippet_4[]
        Generator generator = Generator.create(outputStream);

        generator.writeObjectStart();
        generator.write("name", "John");
        generator.write("age", 30);
        generator.writeObjectEnd();
        // end::snippet_4[]
    }

    void snippet_5() {
        // tag::snippet_5[]
        Generator generator = Generator.create(outputStream);

        generator.writeObjectStart();
        generator.writeKey("person");
        generator.writeObjectStart();
        generator.write("name", "John");
        generator.write("age", 30);
        generator.writeObjectEnd();

        generator.writeKey("hobbies");
        generator.writeArrayStart();
        generator.write("reading");
        generator.write("coding");
        generator.writeArrayEnd();
        generator.writeObjectEnd();
        // end::snippet_5[]
    }

    void snippet_6() {
        // tag::snippet_6[]
        JsonObject person = JsonObject.builder()
            .set("name", "John")
            .set("age", 30)
            .set("active", true)
            .build();

        String name = person.stringValue("name", "");
        int age = person.intValue("age", 0);
        boolean active = person.booleanValue("active", false);

        // Nested objects
        JsonObject address = JsonObject.builder()
            .set("street", "123 Main St")
            .set("city", "Springfield")
            .build();

        JsonObject personWithAddress = JsonObject.builder()
            .set("name", "John")
            .set("address", address)
            .build();
        // end::snippet_6[]
    }

    void snippet_7() {
        // tag::snippet_7[]
        JsonArray hobbies = JsonArray.createStrings(List.of("reading", "coding", "gaming"));
        JsonArray numbers = JsonArray.createNumbers(List.of(
            new BigDecimal("1"), new BigDecimal("2"), new BigDecimal("3")));

        // Access elements - JsonArray doesn't provide direct indexed access
        // Use values() to get the list and then access elements
        List<JsonValue> hobbyValues = hobbies.values();
        List<JsonValue> numberValues = numbers.values();
        // end::snippet_7[]
    }

    void snippet_8() {
        // tag::snippet_8[]
        JsonString name = JsonString.create("John Doe");
        String value = name.value(); // "John Doe"

        // From parser
        JsonParser parser = JsonParser.create("\"Hello World\"");
        JsonString greeting = parser.readJsonString();
        // end::snippet_8[]
    }

    void snippet_9() {
        // tag::snippet_9[]
        JsonNumber age = JsonNumber.create(new BigDecimal("30"));
        int intValue = age.intValue();
        double doubleValue = age.doubleValue();
        BigDecimal bigDecimalValue = age.bigDecimalValue();

        // From parser
        JsonParser parser = JsonParser.create("123.45");
        JsonNumber number = parser.readJsonNumber();
        // end::snippet_9[]
    }

    void snippet_10() {
        // tag::snippet_10[]
        JsonBoolean active = JsonBoolean.create(true);
        boolean value = active.value(); // true

        JsonBoolean inactive = JsonBoolean.FALSE; // Predefined constants
        // end::snippet_10[]
    }

    void snippet_11() {
        // tag::snippet_11[]
        JsonNull nullValue = JsonNull.instance();

        // In collections
        JsonArray array = JsonArray.create(List.of(
            JsonString.create("value1"),
            JsonNull.instance(), // null value
            JsonString.create("value3")));
        // end::snippet_11[]
    }

    // tag::snippet_12[]
    @Json.Entity
    public class Person {
        private String name;
        private int age;

        // getters and setters
    }

    JsonBinding binding = JsonBinding.create();
    Person person = binding.deserialize("{\"name\":\"John\",\"age\":30}", Person.class);
    String json = binding.serialize(person);
    // end::snippet_12[]

    void snippet_13() {
        // tag::snippet_13[]
        // Custom JsonSerializer
        public class PersonSerializer implements JsonSerializer<Person> {
            @Override
            public void serialize(Generator generator, Person person, boolean writeNulls) {
                generator.writeObjectStart();
                generator.write("name", person.getName());
                generator.write("age", person.getAge());
                generator.writeObjectEnd();
            }

            @Override
            public GenericType<Person> type() {
                return GenericType.create(Person.class);
            }
        }
        // end::snippet_13[]
    }

    void snippet_14() {
        // tag::snippet_14[]
        // Custom JsonDeserializer
        public class PersonDeserializer implements JsonDeserializer<Person> {
            @Override
            public Person deserialize(JsonParser parser) {
                JsonObject object = parser.readJsonObject();

                String name = object.stringValue("name").orElse("");
                int age = object.intValue("age", 0);

                return new Person(name, age);
            }

            @Override
            public GenericType<Person> type() {
                return GenericType.create(Person.class);
            }
        }
        // end::snippet_14[]
    }

    void snippet_15() {
        // tag::snippet_15[]
        // Using @Json.Converter for combined serializer/deserializer
        @Json.Entity
        public class CustomType {
            @Json.Converter(CustomConverter.class)
            private MyType value;

            // getters and setters
        }

        public class CustomConverter implements JsonConverter<MyType> {
            @Override
            public void serialize(Generator generator, MyType instance, boolean writeNulls) {
                // custom serialization logic
            }

            @Override
            public MyType deserialize(JsonParser parser) {
                // custom deserialization logic
                return null;
            }

            @Override
            public GenericType<MyType> type() {
                return GenericType.create(MyType.class);
            }
        }
        // end::snippet_15[]
    }

    // Stub classes for compilation
    static class Person {
        private String name;
        private int age;

        public Person(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() { return name; }
        public int getAge() { return age; }
    }

    static class MyType {}

    static class BigDecimal {
        public BigDecimal(String s) {}
        public int intValue() { return 0; }
        public double doubleValue() { return 0; }
        public BigDecimal bigDecimalValue() { return null; }
    }

    static class JsonValue {}
    static class Json {
        static class Entity {}
    }
    static class JsonConverter<T> {}
    static class JsonSerializer<T> {}
    static class JsonDeserializer<T> {}

    void snippet_16() {
        // tag::snippet_16[]
        @Json.Entity
        public class Person {
            private String firstName;    // JSON: "firstName"

            @Json.Property("last_name")
            private String lastName;     // JSON: "last_name"

            // getters and setters
        }
        // JSON: {"firstName":"John","last_name":"Doe"}
        // end::snippet_16[]
    }

    void snippet_17() {
        // tag::snippet_17[]
        @Json.Entity
        public class Person {
            private String firstName;
            private String lastName;

            @Json.Property("fullName")
            public String getDisplayName() {  // method becomes "fullName" in JSON
                return firstName + " " + lastName;
            }

            // getters and setters
        }
        // JSON: {"firstName":"John","lastName":"Doe","fullName":"John Doe"}
        // end::snippet_17[]
    }

    void snippet_18() {
        // tag::snippet_18[]
        @Json.Entity
        public class Person {
            private String name;        // included in JSON
            private int age;            // included in JSON

            @Json.Ignore
            private String password;    // excluded from JSON

            // getters and setters
        }
        // JSON: {"name":"John","age":30}
        // end::snippet_18[]
    }

    void snippet_19() {
        // tag::snippet_19[]
        @Json.Entity
        public class Person {
            private String name;             // included
            private transient String temp;   // automatically excluded
            private String data;             // included

            // getters and setters
        }
        // JSON: {"name":"John","data":"value"}
        // end::snippet_19[]
    }

    void snippet_20() {
        // tag::snippet_20[]
        @Json.Entity
        public class Person {
            private String firstName;  // included
            private String lastName;   // included

            @Json.Ignore
            public String getFullName() {  // method excluded from serialization
                return firstName + " " + lastName;
            }

            // other getters and setters
        }
        // JSON: {"firstName":"John","lastName":"Doe"}
        // end::snippet_20[]
    }

    void snippet_21() {
        // tag::snippet_21[]
        @Json.Entity
        public class Person {
            private String name;        // included
            private String email;       // included

            @Json.Ignore                // explicitly ignored
            private String secret;      // excluded

            @Json.Ignore(false)         // explicitly included (default behavior)
            private String publicData;  // included

            // getters and setters
        }
        // JSON: {"name":"John","email":"john@example.com","publicData":"value"}
        // end::snippet_21[]
    }

    void snippet_22() {
        // tag::snippet_22[]
        @Json.Entity
        public class User {
            private String username;     // always included
            private String password;     // should never be serialized

            private transient String sessionToken;  // temp data, excluded

            @Json.Ignore
            private List<String> internalLogs;      // internal state, excluded

            // Only username will appear in JSON
        }
        // JSON: {"username":"john_doe"}
        // end::snippet_22[]
    }

    void snippet_23() {
        // tag::snippet_23[]
        @Json.Entity
        public class PersonDefault {
            private String name;     // "John" -> included
            private Integer age;     // null -> omitted

            // getters and setters
        }
        // JSON: {"name":"John"}
        // end::snippet_23[]
    }

    void snippet_24() {
        // tag::snippet_24[]
        @Json.Entity
        @Json.SerializeNulls
        public class PersonWithNulls {
            private String name;     // "John" -> included
            private Integer age;     // null -> included as null

            // getters and setters
        }
        // JSON: {"name":"John","age":null}
        // end::snippet_24[]
    }

    void snippet_25() {
        // tag::snippet_25[]
        @Json.Entity
        public class PersonSelective {
            private String name;     // "John" -> included

            @Json.SerializeNulls
            private Integer age;     // null -> included as null

            private String city;     // null -> omitted

            // getters and setters
        }
        // JSON: {"name":"John","age":null}
        // end::snippet_25[]
    }

    void snippet_26() {
        // tag::snippet_26[]
        @Json.Entity
        @Json.SerializeNulls
        public class PersonMixed {
            private String name;         // "John" -> included
            private Integer age;         // null -> included as null

            @Json.SerializeNulls(false)  // Override to omit nulls
            private String city;         // null -> omitted

            // getters and setters
        }
        // JSON: {"name":"John","age":null}
        // end::snippet_26[]
    }

    void snippet_27() {
        // tag::snippet_27[]
        @Json.Entity
        public class Person {
            private final String name;
            private final int age;

            @Json.Creator
            public Person(String name, int age) {
                this.name = name;
                this.age = age;
            }

            // getters
        }
        // end::snippet_27[]
    }

    void snippet_28() {
        // tag::snippet_28[]
        @Json.Entity
        public class Person2 {
            private final String name;

            private Person2(String name) {
                this.name = name;
            }

            @Json.Creator
            public static Person2 create(String name) {
                return new Person2(name);
            }
        }
        // end::snippet_28[]
    }

    void snippet_29() {
        // tag::snippet_29[]
        @Json.Entity
        @Json.PropertyOrder(Order.ALPHABETICAL)
        public class Person {
            private String name;
            private int age;
            private String city;

            // getters and setters
        }
        // end::snippet_29[]
    }

    void snippet_30() {
        // tag::snippet_30[]
        @Json.Entity
        public class PersonDefault {
            private String zebra;    // appears first in JSON
            private String alpha;    // appears second in JSON
            private String beta;     // appears third in JSON
        }
        // JSON: {"zebra":"value","alpha":"value","beta":"value"}
        // end::snippet_30[]
    }

    void snippet_31() {
        // tag::snippet_31[]
        @Json.Entity
        @Json.PropertyOrder(Order.ALPHABETICAL)
        public class PersonAlphabetical {
            private String zebra;    // appears third in JSON
            private String alpha;    // appears first in JSON
            private String beta;     // appears second in JSON
        }
        // JSON: {"alpha":"value","beta":"value","zebra":"value"}
        // end::snippet_31[]
    }

    void snippet_32() {
        // tag::snippet_32[]
        @Json.Entity
        @Json.PropertyOrder({"city", "name", "age"})
        public class PersonCustom {
            private String name;     // appears second in JSON
            private int age;         // appears third in JSON
            private String city;     // appears first in JSON
        }
        // JSON: {"city":"value","name":"value","age":30}
        // end::snippet_32[]
    }

    void snippet_33() {
        // tag::snippet_33[]
        @Json.Entity
        @Json.PropertyOrder(Order.REVERSE_ALPHABETICAL)
        public class PersonReverse {
            private String alpha;    // appears third in JSON
            private String beta;     // appears second in JSON
            private String zebra;    // appears first in JSON
        }
        // JSON: {"zebra":"value","beta":"value","alpha":"value"}
        // end::snippet_33[]
    }

    void snippet_34() {
        // tag::snippet_34[]
        @Json.Entity
        public class CustomType {

            @Json.Deserializer(CustomDeserializer.class)
            private MyType value;

            // getters and setters
        }

        public class CustomDeserializer implements JsonDeserializer<MyType> {
            @Override
            public MyType deserialize(JsonParser parser) {
                // custom deserialization logic
                return null;
            }
        }
        // end::snippet_34[]
    }

    void snippet_35() {
        // tag::snippet_35[]
        @Json.Entity
        @Json.BuilderInfo(PersonBuilder.class)
        public class Person {
            private final String name;
            private final int age;

            // constructor, getters
        }

        public class PersonBuilder {
            private String name;
            private int age;

            public PersonBuilder name(String name) {
                this.name = name;
                return this;
            }

            public PersonBuilder age(int age) {
                this.age = age;
                return this;
            }

            public Person build() {
                return new Person(name, age);
            }
        }
        // end::snippet_35[]
    }

    void snippet_36() {
        // tag::snippet_36[]
        @Json.Entity
        @Json.FailOnUnknown
        public class StrictPerson {
            private String name;

            // getters and setters
        }
        // end::snippet_36[]
    }

    void snippet_37() {
        // tag::snippet_37[]
        @Json.Entity
        public class Person {
            @Json.Required
            private String name;

            private Integer age; // optional

            // getters and setters
        }
        // end::snippet_37[]
    }

    void snippet_38() {
        // tag::snippet_38[]
        @Json.Entity
        public class Person {
            private final String name;
            private final int age;

            @Json.Creator
            public Person(String name, int age) {
                this.name = name;
                this.age = age;
            }

            // getters
        }
        // end::snippet_38[]
    }

    void snippet_39() {
        // tag::snippet_39[]
        @Json.Entity
        public class Person2 {
            private final String name;

            private Person2(String name) {
                this.name = name;
            }

            @Json.Creator
            public static Person2 create(String name) {
                return new Person2(name);
            }
        }
        // end::snippet_39[]
    }

    void snippet_40() {
        // tag::snippet_40[]
        @Json.Entity
        @Json.PropertyOrder(Order.ALPHABETICAL)
        public class Person {
            private String name;
            private int age;
            private String city;

            // getters and setters
        }
        // end::snippet_40[]
    }

    void snippet_41() {
        // tag::snippet_41[]
        @Json.Entity
        public class PersonDefault {
            private String zebra;    // appears first in JSON
            private String alpha;    // appears second in JSON
            private String beta;     // appears third in JSON
        }
        // JSON: {"zebra":"value","alpha":"value","beta":"value"}
        // end::snippet_41[]
    }

    void snippet_42() {
        // tag::snippet_42[]
        @Json.Entity
        @Json.PropertyOrder(Order.ALPHABETICAL)
        public class PersonAlphabetical {
            private String zebra;    // appears third in JSON
            private String alpha;    // appears first in JSON
            private String beta;     // appears second in JSON
        }
        // JSON: {"alpha":"value","beta":"value","zebra":"value"}
        // end::snippet_42[]
    }

    void snippet_43() {
        // tag::snippet_43[]
        @Json.Entity
        @Json.PropertyOrder({"city", "name", "age"})
        public class PersonCustom {
            private String name;     // appears second in JSON
            private int age;         // appears third in JSON
            private String city;     // appears first in JSON
        }
        // JSON: {"city":"value","name":"value","age":30}
        // end::snippet_43[]
    }

    void snippet_44() {
        // tag::snippet_44[]
        @Json.Entity
        @Json.PropertyOrder(Order.REVERSE_ALPHABETICAL)
        public class PersonReverse {
            private String alpha;    // appears third in JSON
            private String beta;     // appears second in JSON
            private String zebra;    // appears first in JSON
        }
        // JSON: {"zebra":"value","beta":"value","alpha":"value"}
        // end::snippet_44[]
    }

    void snippet_45() {
        // tag::snippet_45[]
        @Json.Entity
        public class CustomType {

            @Json.Deserializer(CustomDeserializer.class)
            private MyType value;

            // getters and setters
        }

        public class CustomDeserializer implements JsonDeserializer<MyType> {
            @Override
            public MyType deserialize(JsonParser parser) {
                // custom deserialization logic
                return null;
            }
        }
        // end::snippet_45[]
    }

    void snippet_46() {
        // tag::snippet_46[]
        @Json.Entity
        @Json.BuilderInfo(PersonBuilder.class)
        public class Person {
            private final String name;
            private final int age;

            // constructor, getters
        }

        public class PersonBuilder {
            private String name;
            private int age;

            public PersonBuilder name(String name) {
                this.name = name;
                return this;
            }

            public PersonBuilder age(int age) {
                this.age = age;
                return this;
            }

            public Person build() {
                return new Person(name, age);
            }
        }
        // end::snippet_46[]
    }

    void snippet_47() {
        // tag::snippet_47[]
        @Json.Entity
        @Json.FailOnUnknown
        public class StrictPerson {
            private String name;

            // getters and setters
        }
        // end::snippet_47[]
    }

    // Stub variables
    java.io.OutputStream outputStream = null;
}
