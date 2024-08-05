package io.helidon.json.processor;

import java.util.Map;

/**
 * TODO javadoc
 */
public final class JsonObject implements JsonValue {

    private final Map<String, Object> content;

    JsonObject(Map<String, Object> content) {
        this.content = content;
    }

    public String getString(String key, String defaultValue) {
        Object o = content.get(key);
        return o == null ? defaultValue : ((JsonString) o).resolveString();
    }

    public Double getDouble(String key, Double defaultValue) {
        JsonNumber o = (JsonNumber) content.get(key);
        return o == null ? defaultValue : Double.valueOf(o.asDouble());
    }

    public Long getLong(String key, Long defaultValue) {
        JsonNumber o = (JsonNumber) content.get(key);
        return o == null ? defaultValue : Long.valueOf((long) o.asDouble());
    }

    public Integer getInt(String key, Integer defaultValue) {
        JsonNumber o = (JsonNumber) content.get(key);
        return o == null ? defaultValue : Integer.valueOf((int) o.asDouble());
    }

    public Float getFloat(String key, Float defaultValue) {
        JsonNumber o = (JsonNumber) content.get(key);
        return o == null ? defaultValue : Float.valueOf((float) o.asDouble());
    }

    public Boolean getBoolean(String key, Boolean defaultValue) {
        Boolean booleanValue = (Boolean) content.get(key);
        return booleanValue == null ? defaultValue : booleanValue;
    }

    public JsonObject getObject(String key, JsonObject defaultValue) {
        JsonObject object = (JsonObject) content.get(key);
        return object == null ? defaultValue : object;
    }

    public boolean containsKey(String key) {
        return content.containsKey(key);
    }


}
