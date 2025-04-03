package io.helidon.json.binding.converters;

import io.helidon.common.GenericType;
import io.helidon.common.Weight;
import io.helidon.common.Weighted;
import io.helidon.json.binding.JsonBindingConfigurer;
import io.helidon.service.registry.Service;

//@Service.Singleton
//@Weight(Weighted.DEFAULT_WEIGHT - 10)
class IntArrayConverter extends ArrayConverter<Integer> {

    IntArrayConverter() {
        super(Integer.class);
    }

    @Override
    protected Integer[] createArrayInstance(int size) {
        return new Integer[size];
    }

    @Override
    public GenericType<Integer[]> type() {
        return new GenericType<>() { };
    }
}
