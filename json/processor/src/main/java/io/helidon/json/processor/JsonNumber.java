package io.helidon.json.processor;

import java.math.BigDecimal;

/**
 * TODO javadoc
 */
public final class JsonNumber implements JsonValue {

    private final byte[] buffer;
    private final int start;
    private Double doubleValue;
    private Integer intValue;
    private BigDecimal bigDecimalValue;

    private JsonNumber(byte[] buffer, int start) {
        this.buffer = buffer;
        this.start = start;
    }

    private JsonNumber(BigDecimal bigDecimalValue) {
        this.buffer = JsonValues.EMPTY_BYTES;
        this.start = -1;
        this.bigDecimalValue = bigDecimalValue;
        this.intValue = bigDecimalValue.intValue();
        this.doubleValue = bigDecimalValue.doubleValue();
    }

    public static JsonNumber create(BigDecimal bigDecimalValue) {
        return new JsonNumber(bigDecimalValue);
    }

    static JsonNumber create(byte[] buffer, int start) {
        return new JsonNumber(buffer, start);
    }

    public double doubleValue() {
        if (doubleValue == null) {
            CachedParser cachedParser = JsonParserCache.getCachedParser();
            ReusableJsonParser parser = cachedParser.get();
            parser.reset(buffer, start);
            doubleValue = parser.readAsDouble();
            cachedParser.set(parser);
        }
        return doubleValue;
    }

    public int intValue() {
        if (intValue == null) {
            CachedParser cachedParser = JsonParserCache.getCachedParser();
            ReusableJsonParser parser = cachedParser.get();
            parser.reset(buffer, start);
            intValue = parser.readAsInt();
            cachedParser.set(parser);
        }
        return intValue;
    }

    public BigDecimal bigDecimalValue() {
        if (bigDecimalValue == null) {
            CachedParser cachedParser = JsonParserCache.getCachedParser();
            ReusableJsonParser parser = cachedParser.get();
            parser.reset(buffer, start);
            bigDecimalValue = new BigDecimal(parser.readNumberAsArray());
            cachedParser.set(parser);
        }
        return bigDecimalValue;
    }

    @Override
    public JsonValueType type() {
        return JsonValueType.NUMBER;
    }

    @Override
    public void toJson(Generator generator) {
        BigDecimal bigDecimal = bigDecimalValue();
        if (bigDecimal.stripTrailingZeros().scale() <= 0) {
            generator.write(bigDecimal.longValue());
        } else {
            generator.write(bigDecimal.doubleValue());
        }
    }
}
