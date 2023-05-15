package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
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
    private final List<Field> fields;
    private final List<Field> staticFields;
    private final List<Method> methods;
    private final List<Method> staticMethods;
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
        this.fields = builder.fields.values().stream().sorted().toList();
        this.staticFields = builder.staticFields.values().stream().sorted().toList();
        this.methods = builder.methods.stream().sorted().toList();
        this.staticMethods = builder.staticMethods.stream().sorted().toList();
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
            writeClassFields(staticFields, writer, combinedTokens, imports);
        }
        if (!fields.isEmpty()) {
            writeClassFields(fields, writer, combinedTokens, imports);
        }
        if (!constructors.isEmpty()) {
            writerClassConstructors(writer, combinedTokens, imports);
        }
        if (!staticMethods.isEmpty()) {
            writerClassMethods(staticMethods, writer, combinedTokens, imports);
        }
        if (!methods.isEmpty()) {
            writerClassMethods(methods, writer, combinedTokens, imports);
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

    private void writerClassMethods(List<Method> methods, ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException {
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

    List<Field> fields() {
        return fields;
    }

    List<Field> staticFields() {
        return staticFields;
    }

    List<Method> methods() {
        return methods;
    }
    List<Method> staticMethods() {
        return staticMethods;
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

        private final Set<Method> methods = new HashSet<>();
        private final Set<Method> staticMethods = new HashSet<>();
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

        void commonBuildLogic() {
        }

        public B description(String description) {
            this.javadocBuilder.add(description);
            this.javadocBuilder.generate(true);
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
            return inheritance(Type.exact(inheritance));
        }

        public B inheritance(Type inheritance) {
            this.inheritance = inheritance;
            return me;
        }

        public B addField(Field.Builder builder) {
            return addField(builder.build());
        }

        public B addField(Field field) {
            String fieldName = field.name();
            if (field.isStatic()) {
                fields.remove(fieldName);
                staticFields.put(fieldName, field);
            } else {
                staticFields.remove(fieldName);
                fields.put(fieldName, field);
            }
            return me;
        }

        public B addMethod(Method.Builder builder) {
            return addMethod(builder.build());
        }

        public B addMethod(Method method) {
            methods.remove(method);
            staticMethods.remove(method);
            if (method.isStatic()) {
                staticMethods.add(method);
            } else {
                methods.add(method);
            }
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
            return addInterface(Type.exact(interfaceName));
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

        public B addConstructor(Consumer<Constructor.Builder> supplier) {
            Constructor.Builder constructorBuilder = Constructor.builder(name);
            supplier.accept(constructorBuilder);
            constructors.add(constructorBuilder.build());
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

        Set<Method> staticMethod() {
            return staticMethods;
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
