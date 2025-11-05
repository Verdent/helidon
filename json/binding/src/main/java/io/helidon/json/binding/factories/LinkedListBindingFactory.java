package io.helidon.json.binding.factories;

import java.lang.reflect.Type;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonDeserializer;
import io.helidon.json.binding.JsonSerializer;
import io.helidon.service.registry.Service;

@Service.Singleton
@Weight(Weighted.DEFAULT_WEIGHT - 10)
class LinkedListBindingFactory extends ListBindingFactory {

    @Override
    public JsonDeserializer<List<?>> createDeserializer(Type type) {
        return new LinkedListConverter(type);
    }

    @Override
    public JsonSerializer<List<?>> createSerializer(Type type) {
        return new LinkedListConverter(type);
    }

    @Override
    public Set<Class<?>> supportedTypes() {
        return Set.of(LinkedList.class);
    }

    private static final class LinkedListConverter extends ListConverter {

        LinkedListConverter(Type type) {
            super(type);
        }

        @Override
        List<Object> createInstance(int size) {
            return new LinkedList<>();
        }

    }

}
