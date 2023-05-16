package io.helidon.builder.processor.tools;

import java.util.ArrayList;

import io.helidon.builder.processor.tools.model.Annotation;
import io.helidon.builder.processor.tools.model.ClassModel;
import io.helidon.builder.processor.tools.model.Field;
import io.helidon.builder.processor.tools.model.Method;
import io.helidon.builder.processor.tools.model.Parameter;
import io.helidon.builder.processor.tools.model.Type;

import org.junit.jupiter.api.Test;

public class DogTest {

    @Test
    public void dogTest() {
        ClassModel classModel = ClassModel.builder("my.perfect.pet", "Dog")
                .description("My perfect dog.")
                .addField(Field.builder("name", String.class).isFinal(true))
                .addField(Field.builder("age", int.class))
                .addField(Field.builder("list",
                                        Type.generic(ArrayList.class)
                                                .addParam("my.other.test.CustomClass")
                                                .build())
                                  .defaultValue("new ArrayList<>()"))
                .addMethod(Method.builder("name")
                                   .returnType(String.class, "name of the dog")
                                   .description("Return the name of the dog.")
                                   .addLine("return name;"))
                .addMethod(Method.builder("toString")
                                   .returnType(String.class)
                                   .addAnnotation(Annotation.create(Override.class))
                                   .addLine("return name + \" \" + age;"))
                .addMethod(Method.builder("main")
                                   .description("My main method")
                                   .isStatic(true)
                                   .addParameter(Parameter.builder("args", String[].class).description("my param"))
                                   .addLine("if (args.length == 0) {")
                                   .padding().addLine("System.out.println(\"Empty\");")
                                   .addLine("}"))
                .build();

        System.out.println(classModel.toString());
    }

}
