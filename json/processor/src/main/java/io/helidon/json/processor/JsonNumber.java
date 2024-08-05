package io.helidon.json.processor;

import java.util.stream.IntStream;

/**
 * TODO javadoc
 */
public class JsonNumber implements JsonValue {

    private static final int UNICODE_NUMBER_BASE = -48;

    private static final boolean[] DIGIT_CHAR = new boolean[200];
    static {
        IntStream.range('0', '9' + 1).forEach(value -> DIGIT_CHAR[value] = true);
    }

    private static final long[] POW_CACHE = new long[] {
            1,
            10,
            100,
            1000,
            10000,
            100000,
            1000000,
            10000000,
            100000000,
            1000000000,
            10000000000L,
            100000000000L,
            1000000000000L,
            10000000000000L,
            100000000000000L,
            1000000000000000L,
            10000000000000000L,
            100000000000000000L,
            1000000000000000000L,
    };

    private final char[] numberChars;
    private Double value;
    private int index = 0;

    public JsonNumber(char[] numberChars) {
        this.numberChars = numberChars;
    }

    public double asDouble() {
        if (value != null) {
            return value;
        }
        boolean negative = numberChars[0] == '-';
        if (negative || numberChars[0] == '+') {
            index++;
        }
        if (index == numberChars.length) {
            throw new JsonException("Number should not be only - or +");
        }
        long val = readLong();
        if (index == numberChars.length) {
            value = (double) val;
            if (negative) {
                value = -value;
            }
            return value;
        }
        if (numberChars[index] == '.') {
            int decimalStart = ++index;
            long decimal = readLong();
            int decimalDigits = index - decimalStart;
            if (index == numberChars.length) {
                if (decimalDigits >= POW_CACHE.length) {
                    //Let Java handle the rest
                    throw new IllegalStateException("Should not be here");
                } else {
                    value = val + (decimal / (double) POW_CACHE[decimalDigits]);
                    if (negative) {
                        value = -value;
                    }
                }
            } else {
                //Let Java evaluate E notation etc.
                value = Double.parseDouble(new String(numberChars));
            }
        } else {
            //Let Java evaluate E notation etc.
            throw new IllegalStateException("Should not be here");
        }
        return value;
    }

    private long readLong() {
        long result = 0;
        for ( ; index < numberChars.length; index++) {
            char numberChar = numberChars[index];
            if (numberChar == 'E' || numberChar == 'e' || numberChar == '.') {
                break;
            } else if (numberChar > DIGIT_CHAR.length || !DIGIT_CHAR[numberChar]) {
                throw new JsonException("Invalid number: " + new String(numberChars));
            }
            result = result * 10 + (UNICODE_NUMBER_BASE + numberChar);
        }
        return result;
    }

}
