package io.helidon.common;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Objects;

class HelidonParameterizedType implements ParameterizedType {

    private final Class<?> type;
    private final Type[] typeArgs;

    HelidonParameterizedType(Class<?> type, Type[] typeArgs) {
        this.type = type;
        this.typeArgs = Arrays.copyOf(typeArgs, typeArgs.length);
    }

    @Override
    public Type[] getActualTypeArguments() {
        return typeArgs;
    }

    @Override
    public Type getRawType() {
        return type;
    }

    @Override
    public Type getOwnerType() {
        return null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        HelidonParameterizedType that = (HelidonParameterizedType) o;
        return Objects.equals(type, that.type)
                && Arrays.equals(typeArgs, that.typeArgs);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(type);
        result = 31 * result + Arrays.hashCode(typeArgs);
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(type.toString());
        if (typeArgs.length > 0) {
            sb.append("<");
            for (Type typeArg : typeArgs) {
                sb.append(typeArg);
            }
            sb.append(">");
        }
        return sb.toString();
    }

}
