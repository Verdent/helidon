package io.helidon.json.binding;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

import io.helidon.common.GenericType;

/**
 * TODO javadoc
 */
public interface TypedJsonConverter<T> extends TypedJsonSerializer<T>, TypedJsonDeserializer<T> {

    default GenericType<T> type() {
        for (Type type : getClass().getGenericInterfaces()) {
            if (type instanceof ParameterizedType parameterizedType
                    && parameterizedType.getRawType().equals(TypedJsonConverter.class)) {
                return GenericType.create(parameterizedType.getActualTypeArguments()[0]);
            }
        }
        throw new IllegalStateException("This should never be reached.");
    }

}
