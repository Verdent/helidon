package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.stream.Collectors.groupingBy;

public class AbstractClass {

    private final String name;
    private final Type inheritance;
    private final boolean isFinal;
    private final boolean isAbstract;
    private final boolean isStatic;
    private final AccessModifier accessModifier;
    private final Map<String, Field> fields;
    private final Map<String, Field> staticFields;
    private final Set<Method> methods;
    private final Set<Type> interfaces;
    private final Set<String> tokenNames;
    private final List<Constructor> constructors;
    private final List<Token> genericParameters;
    private final List<InnerClass> innerClasses;
    private final List<Annotation> annotations;
    private final Javadoc javadoc;

    AbstractClass(Builder<?, ?> builder) {
        this.name = builder.name;
        this.isFinal = builder.isFinal;
        this.isAbstract = builder.isAbstract;
        this.isStatic = builder.isStatic;
        this.accessModifier = builder.accessModifier;
        this.fields = new LinkedHashMap<>(builder.fields);
        this.staticFields = new LinkedHashMap<>(builder.staticFields);
        this.methods = new LinkedHashSet<>(builder.methods);
        this.inheritance = builder.inheritance;
        this.constructors = List.copyOf(builder.constructors);
        this.interfaces = Set.copyOf(builder.interfaces);
        this.innerClasses = List.copyOf(builder.innerClasses.values());
        this.annotations = List.copyOf(builder.annotations);
        this.genericParameters = List.copyOf(builder.genericParameters);
        this.tokenNames = this.genericParameters.stream()
                .map(Token::token)
                .collect(Collectors.toSet());
        this.javadoc = builder.javadocBuilder.build();
    }

    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        Set<String> combinedTokens = Stream.concat(declaredTokens.stream(), this.tokenNames.stream()).collect(Collectors.toSet());
        if (javadoc.shouldGenerate(accessModifier)) {
            javadoc.writeComponent(writer, combinedTokens, imports);
            writer.write("\n");
        }
        if (!annotations.isEmpty()) {
            for (Annotation annotation : annotations) {
                annotation.writeComponent(writer, combinedTokens, imports);
                writer.write("\n");
            }
        }
        if (AccessModifier.PACKAGE_PRIVATE != accessModifier) {
            writer.write(accessModifier.modifierName() + " ");
        }
        if (isStatic) {
            writer.write("static ");
        }
        if (isFinal) {
            writer.write("final ");
        }
        if (isAbstract) {
            if (isFinal) {
                throw new IllegalStateException("Class cannot be abstract and final");
            }
            writer.write("abstract ");
        }
        writer.write("class " + name);
        if (!genericParameters.isEmpty()) {
            writeGenericParameters(writer, combinedTokens, imports);
        }
        writer.write(" ");
        if (inheritance != null) {
            writer.write("extends ");
            inheritance.writeComponent(writer, combinedTokens, imports);
            writer.write(" ");
        }
        if (!interfaces.isEmpty()) {
            writeClassInterfaces(writer, combinedTokens, imports);
        }
        writer.write("{\n");
        if (!staticFields.isEmpty()) {
            writeClassFields(staticFields.values(), writer, combinedTokens, imports);
        }
        if (!fields.isEmpty()) {
            writeClassFields(fields.values(), writer, combinedTokens, imports);
        }
        if (!constructors.isEmpty()) {
            writerClassConstructors(writer, combinedTokens, imports);
        }
        if (!methods.isEmpty()) {
            writerClassMethods(writer, combinedTokens, imports);
        }
        if (!innerClasses.isEmpty()) {
            writeInnerClasses(writer, combinedTokens, imports);
        }
        writer.write("\n");
        writer.write("}");
    }

    private void writeGenericParameters(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        writer.write("<");
        boolean first = true;
        for (Type parameter : genericParameters) {
            if (first) {
                first = false;
            } else {
                writer.write(", ");
            }
            parameter.writeComponent(writer, declaredTokens, imports);
        }
        writer.write(">");
    }

    private void writeClassInterfaces(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        writer.write("implements ");
        boolean first = true;
        for (Type interfaceName : interfaces) {
            if (first) {
                first = false;
            } else {
                writer.write(", ");
            }
            interfaceName.writeComponent(writer, declaredTokens, imports);
        }
        writer.write(" ");
    }

    private void writeClassFields(Collection<Field> fields,
                                  ModelWriter writer,
                                  Set<String> declaredTokens,
                                  ImportOrganizer imports) throws IOException {
        writer.increasePaddingLevel();
        for (Field field : fields) {
            writer.write("\n");
            field.writeComponent(writer, declaredTokens, imports);
        }
        writer.decreasePaddingLevel();
        writer.write("\n");
    }
    private void writerClassConstructors(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        writer.increasePaddingLevel();
        for (Constructor constructor : constructors) {
            writer.write("\n");
            constructor.writeComponent(writer, declaredTokens, imports);
            writer.write("\n");
        }
        writer.decreasePaddingLevel();
    }

    private void writerClassMethods(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        writer.increasePaddingLevel();
        for (Method method : methods) {
            writer.write("\n");
            method.writeComponent(writer, declaredTokens, imports);
            writer.write("\n");
        }
        writer.decreasePaddingLevel();
    }

    private void writeInnerClasses(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
        writer.increasePaddingLevel();
        for (InnerClass innerClass : innerClasses) {
            writer.write("\n");
            innerClass.writeComponent(writer, declaredTokens, imports);
            writer.write("\n");
        }
        writer.decreasePaddingLevel();
    }

    Type inheritance() {
        return inheritance;
    }

    Map<String, Field> fields() {
        return fields;
    }

    Map<String, Field> staticFields() {
        return staticFields;
    }

    Set<Method> methods() {
        return methods;
    }

    Set<Type> interfaces() {
        return interfaces;
    }

    List<Annotation> annotations() {
        return annotations;
    }

    List<Constructor> constructors() {
        return constructors;
    }

    List<Token> genericParameters() {
        return genericParameters;
    }

    public static abstract class Builder<T extends AbstractClass, B extends Builder<T, B>> {

        private final Set<Method> methods = new LinkedHashSet<>();
        private final Map<String, Field> fields = new LinkedHashMap<>();
        private final Map<String, Field> staticFields = new LinkedHashMap<>();
        private final Map<String, InnerClass> innerClasses = new LinkedHashMap<>();
        private final List<Annotation> annotations = new ArrayList<>();
        private final List<Constructor> constructors = new ArrayList<>();
        private final List<Token> genericParameters = new ArrayList<>();
        private final Set<Type> interfaces = new HashSet<>();
        private final Javadoc.Builder javadocBuilder = Javadoc.builder();
        private final String name;
        private Type inheritance;
        private boolean isFinal = false;
        private boolean isAbstract = false;
        private boolean isStatic = false;
        private AccessModifier accessModifier = AccessModifier.PUBLIC;
        private final B me;

        Builder(String name) {
            this.name = Objects.requireNonNull(name);
            this.me = (B) this;
        }

        public abstract T build();

//        public T build() {
//            Map<String, List<Field>> collect = fields.values().stream().collect(groupingBy(AbstractComponent::type));
//            fields.clear();
//
//            collect.keySet()
//                    .stream()
//                    .sorted()
//                    .map(collect::get)
//                    .forEach(list -> list.stream().sorted(Comparator.comparing(Field::name))
//                            .forEach(field -> fields.put(field.name(), field)));
//
//            fields.values().forEach(field -> field.addImports(imports));
//            methods.values().forEach(method -> method.addImports(imports));
//            interfaces.forEach(imports::addImport);
//            if (inheritance != null) {
//                inheritance.addImports(imports);
//            }
//            return new ClassModel(this);
//        }
        void commonBuildLogic() {
            //TODO prepsat
            Map<String, List<Field>> collect = fields.values().stream().collect(groupingBy(field -> field.type().typeName()));
            fields.clear();

            collect.keySet()
                    .stream()
                    .sorted()
                    .map(collect::get)
                    .forEach(list -> list.stream().sorted(Comparator.comparing(Field::name))
                            .forEach(field -> {
                                if (field.isStatic()) {
                                    staticFields.put(field.name(), field);
                                } else {
                                    fields.put(field.name(), field);
                                }
                            }));
        }

        public B description(String description) {
            this.javadocBuilder.add(description);
            return me;
        }

        public B addAuthor(String author) {
            this.javadocBuilder.addAuthor(author);
            return me;
        }

        public B isFinal(boolean isFinal) {
            this.isFinal = isFinal;
            return me;
        }

        public B isAbstract(boolean isAbstract) {
            this.isAbstract = isAbstract;
            return me;
        }

        B isStatic(boolean isStatic) {
            this.isStatic = isStatic;
            return me;
        }

        public B accessModifier(AccessModifier accessModifier) {
            this.accessModifier = accessModifier;
            return me;
        }

        public B inheritance(Class<?> inheritance) {
            return inheritance(inheritance.getName());
        }

        public B inheritance(String inheritance) {
            return inheritance(Type.create(inheritance));
        }

        public B inheritance(Type inheritance) {
            this.inheritance = inheritance;
            return me;
        }

        public B addField(Field.Builder builder) {
            return addField(builder.build());
        }

        public B addField(Field field) {
            fields.put(field.name(), field);
            return me;
        }

        public B addMethod(Method.Builder builder) {
            return addMethod(builder.build());
        }

        public B addMethod(Method method) {
            methods.add(method);
            return me;
        }

        public B addInterface(Class<?> interfaceType) {
            if (interfaceType.isInterface()) {
                return addInterface(interfaceType.getName());
            } else {
                throw new IllegalArgumentException("Provided value needs to be interface, but it was not: " + interfaceType.getName());
            }
        }

        public B addInterface(String interfaceName) {
            return addInterface(Type.create(interfaceName));
        }

        public B addInterface(Type interfaceType) {
            interfaces.add(interfaceType);
            return me;
        }

        public B addInnerClass(InnerClass innerClass) {
            this.innerClasses.put(name, innerClass);
            return me;
        }

        public B addAnnotation(Annotation.Builder builder) {
            return addAnnotation(builder.build());
        }

        public B addAnnotation(Annotation annotation) {
            annotations.add(annotation);
            return me;
        }

        public B addConstructor(Constructor constructor) {
            constructors.add(constructor);
            return me;
        }

        public B addGenericParameter(Token token) {
            this.genericParameters.add(token);
            javadocBuilder.addGenericsToken(token.token(), token.description());
            return me;
        }

        public B addImport(Class<?> typeImport) {
            return addImport(typeImport.getName());
        }

        public abstract B addImport(String importName);

        Set<Method> methods() {
            return methods;
        }

        Map<String, Field> fields() {
            return fields;
        }

        Map<String, Field> staticFields() {
            return staticFields;
        }

        Set<Type> interfaces() {
            return interfaces;
        }

        List<Annotation> annotations() {
            return annotations;
        }

        List<Constructor> constructors() {
            return constructors;
        }

        Type inheritance() {
            return inheritance;
        }

        Map<String, InnerClass> innerClasses() {
            return innerClasses;
        }

        List<Token> genericParameters() {
            return genericParameters;
        }
    }
}
