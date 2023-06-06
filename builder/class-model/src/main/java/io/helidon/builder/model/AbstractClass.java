package io.helidon.builder.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public abstract class AbstractClass extends AnnotatableComponent {

    private final boolean isFinal;
    private final boolean isAbstract;
    private final boolean isStatic;
    private final List<Field> fields;
    private final List<Field> staticFields;
    private final List<Method> methods;
    private final List<Method> staticMethods;
    private final Set<Type> interfaces;
    private final Set<String> tokenNames;
    private final List<Constructor> constructors;
    private final List<Token> genericParameters;
    private final List<InnerClass> innerClasses;

    AbstractClass(Builder<?, ?> builder) {
        super(builder);
        this.isFinal = builder.isFinal;
        this.isAbstract = builder.isAbstract;
        this.isStatic = builder.isStatic;
        this.fields = builder.fields.values().stream().sorted().toList();
        this.staticFields = builder.staticFields.values().stream().sorted().toList();
        this.methods = builder.methods.stream().sorted().toList();
        this.staticMethods = builder.staticMethods.stream().sorted().toList();
        this.constructors = List.copyOf(builder.constructors);
        this.interfaces = Set.copyOf(builder.interfaces);
        this.innerClasses = List.copyOf(builder.innerClasses.values());
        this.genericParameters = List.copyOf(builder.genericParameters);
        this.tokenNames = this.genericParameters.stream()
                .map(Token::token)
                .collect(Collectors.toSet());
    }

    @Override
    void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws
            IOException {
        Set<String> combinedTokens = Stream.concat(declaredTokens.stream(), this.tokenNames.stream()).collect(Collectors.toSet());
        if (javadoc().generate()) {
            javadoc().writeComponent(writer, combinedTokens, imports);
            writer.write("\n");
        }
        if (!annotations().isEmpty()) {
            for (Annotation annotation : annotations()) {
                annotation.writeComponent(writer, combinedTokens, imports);
                writer.write("\n");
            }
        }
        if (AccessModifier.PACKAGE_PRIVATE != accessModifier()) {
            writer.write(accessModifier().modifierName() + " ");
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
        writer.write("class " + name());
        if (!genericParameters.isEmpty()) {
            writeGenericParameters(writer, combinedTokens, imports);
        }
        writer.write(" ");
        if (type() != null) {
            writer.write("extends ");
            type().writeComponent(writer, combinedTokens, imports);
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

    private void writeGenericParameters(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports)
            throws IOException {
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

    private void writeClassInterfaces(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports)
            throws IOException {
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

    private void writerClassConstructors(ModelWriter writer,
                                         Set<String> declaredTokens,
                                         ImportOrganizer imports) throws IOException {
        writer.increasePaddingLevel();
        for (Constructor constructor : constructors) {
            writer.write("\n");
            constructor.writeComponent(writer, declaredTokens, imports);
            writer.write("\n");
        }
        writer.decreasePaddingLevel();
    }

    private void writerClassMethods(List<Method> methods,
                                    ModelWriter writer,
                                    Set<String> declaredTokens,
                                    ImportOrganizer imports) throws IOException {
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

    @Override
    void addImports(ImportOrganizer.Builder imports) {
        super.addImports(imports);
        fields.forEach(field -> field.addImports(imports));
        staticFields.forEach(field -> field.addImports(imports));
        methods.forEach(method -> method.addImports(imports));
        staticMethods.forEach(method -> method.addImports(imports));
        interfaces.forEach(imp -> imp.addImports(imports));
        constructors.forEach(constructor -> constructor.addImports(imports));
        genericParameters.forEach(param -> param.addImports(imports));
    }

    public static abstract class Builder<B extends Builder<B, T>, T extends AbstractClass>
            extends AnnotatableComponent.Builder<B, T> {

        private final Set<Method> methods = new HashSet<>();
        private final Set<Method> staticMethods = new HashSet<>();
        private final Map<String, Field> fields = new LinkedHashMap<>();
        private final Map<String, Field> staticFields = new LinkedHashMap<>();
        private final Map<String, InnerClass> innerClasses = new LinkedHashMap<>();
        private final List<Annotation> annotations = new ArrayList<>();
        private final List<Constructor> constructors = new ArrayList<>();
        private final List<Token> genericParameters = new ArrayList<>();
        private final Set<Type> interfaces = new HashSet<>();
        private ImportOrganizer.Builder importOrganizer = ImportOrganizer.builder();
        private boolean isFinal;
        private boolean isAbstract;
        private boolean isStatic;

        Builder() {
        }

        @Override
        public B accessModifier(AccessModifier accessModifier) {
            return super.accessModifier(accessModifier);
        }

        public B isFinal(boolean isFinal) {
            this.isFinal = isFinal;
            return identity();
        }

        public B isAbstract(boolean isAbstract) {
            this.isAbstract = isAbstract;
            return identity();
        }

        public B inheritance(Class<?> inheritance) {
            return inheritance(inheritance.getName());
        }

        public B inheritance(String inheritance) {
            return inheritance(Type.exact(inheritance));
        }

        public B inheritance(Type inheritance) {
            return super.type(inheritance);
        }

        public B addField(Consumer<Field.Builder> consumer) {
            Field.Builder builder = Field.builder();
            consumer.accept(builder);
            return addField(builder.build());
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
            return identity();
        }

        public B addMethod(Consumer<Method.Builder> consumer) {
            Method.Builder methodBuilder = Method.builder();
            consumer.accept(methodBuilder);
            return addMethod(methodBuilder);
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
            return identity();
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
            return identity();
        }

        public B addInnerClass(Consumer<InnerClass.Builder> consumer) {
            InnerClass.Builder innerClassBuilder = InnerClass.builder()
                    .importOrganizer(importOrganizer);
            consumer.accept(innerClassBuilder);
            InnerClass innerClass = innerClassBuilder.build();
            this.innerClasses.put(innerClass.name(), innerClass);
            return identity();
        }

        public B addConstructor(Consumer<Constructor.Builder> consumer) {
            Constructor.Builder constructorBuilder = Constructor.builder()
                    .type(name());
            consumer.accept(constructorBuilder);
            constructors.add(constructorBuilder.build());
            return identity();
        }

        public B addGenericParameter(Token token) {
            this.genericParameters.add(token);
            return addGenericToken(token.token(), token.description());
        }

        public B addImport(Class<?> typeImport) {
            importOrganizer.addImport(typeImport);
            return identity();
        }

        public B addImport(String importName) {
            importOrganizer.addImport(importName);
            return identity();
        }

        public B addImport(Type type) {
            importOrganizer.addImport(type);
            return identity();
        }

        public B addStaticImport(String staticImport) {
            importOrganizer.addStaticImport(staticImport);
            return identity();
        }

        B importOrganizer(ImportOrganizer.Builder importOrganizer) {
            this.importOrganizer = importOrganizer;
            return identity();
        }

        B isStatic(boolean isStatic) {
            this.isStatic = isStatic;
            return identity();
        }

        ImportOrganizer.Builder importOrganizer() {
            return importOrganizer;
        }
    }
}
