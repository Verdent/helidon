package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.util.Set;

/**
 * TODO javadoc
 */
public abstract class Type {

    public static Type create(Class<?> type) {
        return create(type.getName());
    }

    public static Type create(String typeName) {
        return new ExactType.Builder(typeName).build();
    }

    public static Token token(String token) {
        return new Token.Builder(token).build();
    }

    public static Token.Builder tokenBuilder(String token) {
        return new Token.Builder(token);
    }

    public static ExactType.Builder exact(Class<?> type) {
        return exact(type.getName());
    }

    public static ExactType.Builder exact(String typeName) {
        return new ExactType.Builder(typeName);
    }

    public static GenericType.Builder generic(Class<?> type) {
        return generic(type.getName());
    }

    public static GenericType.Builder generic(String typeName) {
        return new GenericType.Builder(typeName);
    }

    abstract void writeComponent(ModelWriter writer, Set<String> declaredTokens, ImportOrganizer imports) throws IOException;

    abstract void addImports(ImportOrganizer.Builder imports);

    abstract String typeName();
    abstract String simpleTypeName();
    abstract boolean isInnerType();
    abstract boolean isArray();
    abstract String type();
    abstract String outerClass();
    abstract String packageName();


}
