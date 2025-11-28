package io.helidon.json.binding;

import java.util.function.Supplier;

import io.helidon.service.registry.Service;

@Service.Singleton
class JsonBindingProvider implements Supplier<JsonBinding> {

    @Override
    public JsonBinding get() {
        return JsonBinding.create();
    }

}
