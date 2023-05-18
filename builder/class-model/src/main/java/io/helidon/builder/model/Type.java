package io.helidon.builder.model;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;

import io.helidon.common.types.TypeName;
import io.helidon.common.types.TypeNameDefault;

/**
 * TODO javadoc
 */
public abstract class Type extends ModelComponent {

    Type(Builder<?, ?> builder) {
        super(builder);
    }

    public static Type exact(Class<?> type) {
        return exact(type.getTypeName());
    }

    public static Type exact(String typeName) {
        return new ExactType.Builder().type(typeName).build();
    }

    public static ExactType.Builder exactBuilder() {
        return new ExactType.Builder();
    }

    public static Token token(String token) {
        return new Token.Builder().token(token).build();
    }

    public static Token.Builder tokenBuilder() {
        return new Token.Builder();
    }

    public static GenericType.Builder generic() {
        return new GenericType.Builder();
    }

    public static Type fromTypeName(TypeName typeName) {
        return fromTypeName(typeName, false, false);
    }

    //TODO this should accept only one parameter. We need to check whether builder annot processor is correctly done with this.
    public static Type fromTypeName(TypeName typeName, boolean asTopContainer, boolean ignoreTopWildcard) {
        if (typeName.typeArguments().isEmpty()) {
            if (typeName.array()
                    || Optional.class.getName().equals(typeName.declaredName())) {
                return Type.exact(typeName.declaredName());
            } else if (typeName.wildcard() && !ignoreTopWildcard) {
                boolean isObject = typeName.name().equals("?") || Object.class.getName().equals(typeName.name());
                if (isObject) {
                    return Type.token("?");
                } else {
                    return Type.tokenBuilder("?")
                            .bound(fromTypeName(TypeNameDefault.create(typeName.packageName(), typeName.className())))
                            .build();
                }
            }
            return Type.exact(typeName.declaredName());
        }
        GenericType.Builder typeBuilder;
        if (asTopContainer) {
            if (typeName.isList() || typeName.isSet()) {
                typeBuilder = Type.generic(Collection.class);
            } else if (typeName.isMap()) {
                typeBuilder = Type.generic(Map.class);
            } else {
                throw new IllegalStateException("Unsupported type: " + typeName.declaredName());
            }
        } else {
            typeBuilder = Type.generic(typeName.declaredName());
        }
        typeName.typeArguments().stream()
                .map(Type::fromTypeName)
                .forEach(typeBuilder::addParam);
        return typeBuilder.build();
    }

    abstract String typeName();
    abstract String simpleTypeName();
    abstract boolean isArray();
    abstract String packageName();


}
