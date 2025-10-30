package io.helidon.json.processor;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * TODO javadoc
 */
public final class JsonObject implements JsonValue {

    private final List<Pair> pairs;
    private Map<String, JsonValue> content;

    JsonObject(List<Pair> pairs) {
        this.pairs = pairs;
    }

    public boolean containsKey(String key) {
        ensureResolvedKeys();
        return content.containsKey(key);
    }

    public void ensureResolvedKeys() {
        if (content == null) {
            this.content = new HashMap<>(pairs.size());
            CachedParser cachedParser = JsonParserCache.getCachedParser();
            ReusableJsonParser parser = cachedParser.get();
            for (Pair pair : pairs) {
                content.put(pair.key.resolveValue(parser), pair.value);
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

    public JsonValue value(int index, JsonValue defaultValue) {
        if (index < 0 || index >= pairs.size()) {
            return defaultValue;
        }
        Pair pair = pairs.get(index);
        if (pair == null) {
            return defaultValue;
        }
        return pair.value;
    }

    public Optional<JsonValue> value(int index) {
        if (index < 0 || index >= pairs.size()) {
            return Optional.empty();
        }
        Pair pair = pairs.get(index);
        if (pair == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(pair.value);
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

    Optional<BigDecimal> numberValue(String key) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return Optional.empty();
        }
        return Optional.of(jsonValue.asNumber().bigDecimalValue());
    }

    BigDecimal numberValue(String key, BigDecimal defaultValue) {
        ensureResolvedKeys();
        JsonValue jsonValue = content.get(key);
        if (jsonValue == null) {
            return defaultValue;
        }
        return jsonValue.asNumber().bigDecimalValue();
    }

    public int size() {
        return pairs.size();
    }

    @Override
    public JsonValueType type() {
        return JsonValueType.OBJECT;
    }

    public record Pair(JsonString key, JsonValue value) {
    }
}
