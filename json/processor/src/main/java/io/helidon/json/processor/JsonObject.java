package io.helidon.json.processor;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * TODO javadoc
 */
public final class JsonObject extends JsonValue {

    static final JsonObject EMPTY_OBJECT = JsonObject.create(List.of());

    private List<Pair> pairs;
    private LinkedHashMap<String, JsonValue> content;

    private JsonObject(List<Pair> pairs) {
        this.pairs = pairs;
    }

    private JsonObject(LinkedHashMap<String, JsonValue> content) {
        this.content = content;
        this.pairs = new ArrayList<>();
    }

    public static JsonObject.Builder builder() {
        return new Builder();
    }

    public static JsonObject create(Map<String, JsonValue> content) {
        return new JsonObject(new LinkedHashMap<>(content));
    }

    static JsonObject create(List<Pair> pairs) {
        return new JsonObject(pairs);
    }

    @Override
    byte jsonStartChar() {
        return '{';
    }

    public boolean containsKey(String key) {
        ensureResolvedKeys();
        return content.containsKey(key);
    }

    private void ensureResolvedKeys() {
        if (content == null) {
            this.content = new LinkedHashMap<>(pairs.size());
            CachedParser cachedParser = JsonParserCache.getCachedParser();
            ReusableJsonParser parser = cachedParser.get();
            for (Pair pair : pairs) {
                content.put(pair.key.resolveValue(), pair.value);
            }
            cachedParser.set(parser);
        }
    }

    public JsonValue value(String key, JsonValue defaultValue) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return defaultValue;
        }
        return jsonValue;
    }

    public Optional<Boolean> booleanValue(String key) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return Optional.empty();
        }
        return Optional.of(jsonValue.asBoolean().value());
    }

    public boolean booleanValue(String key, boolean defaultValue) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return defaultValue;
        }
        return jsonValue.asBoolean().value();
    }

    public Optional<JsonObject> objectValue(String key) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return Optional.empty();
        }
        return Optional.of(jsonValue.asObject());
    }

    public JsonObject objectValue(String key, JsonObject defaultValue) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return defaultValue;
        }
        return jsonValue.asObject();
    }

    public Optional<String> stringValue(String key) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return Optional.empty();
        }
        return Optional.of(jsonValue.asString().value());
    }

    public String stringValue(String key, String defaultValue) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return defaultValue;
        }
        return jsonValue.asString().value();
    }

    public Optional<Integer> intValue(String key) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return Optional.empty();
        }
        return Optional.of(jsonValue.asNumber().intValue());
    }

    public int intValue(String key, int defaultValue) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return defaultValue;
        }
        return jsonValue.asNumber().intValue();
    }

    public Optional<Double> doubleValue(String key) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return Optional.empty();
        }
        return Optional.of(jsonValue.asNumber().doubleValue());
    }

    public double intValue(String key, double defaultValue) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return defaultValue;
        }
        return jsonValue.asNumber().doubleValue();
    }

    public Optional<BigDecimal> numberValue(String key) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return Optional.empty();
        }
        return Optional.of(jsonValue.asNumber().bigDecimalValue());
    }

    public BigDecimal numberValue(String key, BigDecimal defaultValue) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return defaultValue;
        }
        return jsonValue.asNumber().bigDecimalValue();
    }

    public Set<JsonString> keys() {
        if (pairs.isEmpty() && !content.isEmpty()) {
            content.forEach((key, value) -> {
                pairs.add(new Pair(JsonString.create(key), value));
            });
        }
        return pairs.stream().map(Pair::key).collect(Collectors.toSet());
    }

    public Set<String> keysAsStrings() {
        ensureResolvedKeys();
        return content.keySet();
    }

    public int size() {
        return pairs.size();
    }

    @Override
    public JsonValueType type() {
        return JsonValueType.OBJECT;
    }

    @Override
    public void toJson(Generator generator) {
        ensureResolvedKeys();
        generator.writeObjectStart();
        for (var entry : content.entrySet()) {
            generator.write(entry.getKey(), entry.getValue());
        }
        generator.writeObjectEnd();
    }

    record Pair(JsonString key, JsonValue value) {
    }

    public static final class Builder implements io.helidon.common.Builder<Builder, JsonObject> {
        private final Map<String, JsonValue> values = new LinkedHashMap<>();

        private Builder() {
        }

        @Override
        public JsonObject build() {
            return new JsonObject(new LinkedHashMap<>(values));
        }
        
        public Builder unset(String key) {
            Objects.requireNonNull(key, "key cannot be null");
            values.remove(key);
            return this;
        }
        
        public Builder setNull(String key) {
            values.put(key, JsonNull.instance());
            return this;
        }

        public Builder set(String key, JsonValue value) {
            Objects.requireNonNull(key, "key cannot be null");
            Objects.requireNonNull(value, "value cannot be null");

            values.put(key, value);
            return this;
        }

        public Builder set(String key, Consumer<JsonObject.Builder> consumer) {
            Objects.requireNonNull(key, "key cannot be null");
            Objects.requireNonNull(consumer, "consumer cannot be null");

            JsonObject.Builder builder = JsonObject.builder();
            consumer.accept(builder);
            values.put(key, builder.build());
            return this;
        }
        
        public Builder set(String key, String value) {
            Objects.requireNonNull(key, "key cannot be null");
            Objects.requireNonNull(value, "value cannot be null");

            values.put(key, JsonString.create(value));
            return this;
        }
        
        public Builder set(String key, boolean value) {
            Objects.requireNonNull(key, "key cannot be null");

            values.put(key, JsonBoolean.create(value));
            return this;
        }

        public Builder set(String key, float value) {
            Objects.requireNonNull(key, "key cannot be null");

            return set(key, new BigDecimal(String.valueOf(value)));
        }

        public Builder set(String key, double value) {
            Objects.requireNonNull(key, "key cannot be null");

            return set(key, new BigDecimal(String.valueOf(value)));
        }
        
        public Builder set(String key, int value) {
            Objects.requireNonNull(key, "key cannot be null");

            values.put(key, JsonNumber.create(new BigDecimal(value)));
            return this;
        }

        public Builder set(String key, long value) {
            Objects.requireNonNull(key, "key cannot be null");

            values.put(key, JsonNumber.create(new BigDecimal(value)));
            return this;
        }

        public Builder set(String key, BigDecimal value) {
            Objects.requireNonNull(key, "key cannot be null");
            Objects.requireNonNull(value, "value cannot be null");

            values.put(key, JsonNumber.create(value));
            return this;
        }

        public Builder setValues(String key, List<JsonValue> value) {
            Objects.requireNonNull(key, "key cannot be null");
            Objects.requireNonNull(value, "value cannot be null");

            values.put(key, JsonArray.create(value));
            return this;
        }

        public Builder setStrings(String key, List<String> value) {
            Objects.requireNonNull(key, "key cannot be null");
            Objects.requireNonNull(value, "value cannot be null");

            values.put(key, JsonArray.createStrings(value));
            return this;
        }

        public Builder setLongs(String key, List<Long> value) {
            Objects.requireNonNull(key, "key cannot be null");
            Objects.requireNonNull(value, "value cannot be null");

            values.put(key, JsonArray.createNumbers(value.stream()
                                                             .map(BigDecimal::new)
                                                             .toList()));
            return this;
        }

        public Builder setDoubles(String key, List<Double> value) {
            Objects.requireNonNull(key, "key cannot be null");
            Objects.requireNonNull(value, "value cannot be null");
            values.put(key, JsonArray.createNumbers(value.stream()
                                                             .map(BigDecimal::new)
                                                             .toList()));
            return this;
        }

        public Builder setNumbers(String key, List<BigDecimal> value) {
            Objects.requireNonNull(key, "key cannot be null");
            Objects.requireNonNull(value, "value cannot be null");

            values.put(key, JsonArray.createNumbers(value));
            return this;
        }

        public Builder setBooleans(String key, List<Boolean> value) {
            Objects.requireNonNull(key, "key cannot be null");
            Objects.requireNonNull(value, "value cannot be null");

            values.put(key, JsonArray.createBooleans(value));
            return this;
        }
    }
}
