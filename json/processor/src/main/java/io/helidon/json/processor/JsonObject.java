package io.helidon.json.processor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    public JsonValue get(String key) {
        ensureResolvedKeys();
        return content.get(key);
    }

    public JsonValue get(int index) {
        return pairs.get(index).value;
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
