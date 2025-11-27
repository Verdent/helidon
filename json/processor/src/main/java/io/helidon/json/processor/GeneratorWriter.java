package io.helidon.json.processor;

import java.io.IOException;
import java.io.Writer;

class GeneratorWriter extends AbstractGenerator {

    private static final char[] TRUE = "true".toCharArray();
    private static final char[] FALSE = "false".toCharArray();
    private static final char[] NULL = "null".toCharArray();

    private final Writer writer;

    GeneratorWriter(Writer writer) {
        this.writer = writer;
    }

    @Override
    void writeByte(byte value) {
        try {
            writer.write(value);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    void writeLong(long value) {
        try {
            writer.write(Long.toString(value));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    void writeFloat(float value) {
        try {
            writer.write(Float.toString(value));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    void writeDouble(double value) {
        try {
            writer.write(Double.toString(value));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    void writeString(String value) {
        try {
            writer.write('\"');
            writer.write(value);
            writer.write('\"');
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    void writeChar(char value) {
        try {
            writer.write('\"');
            writer.write(value);
            writer.write('\"');
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    void writeBoolean(boolean value) {
        try {
            if (value) {
                writer.write(TRUE);
            }  else {
                writer.write(FALSE);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    void writeNullValue() {
        try {
            writer.write(NULL);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void close() throws Exception {
        writer.close();
    }
}
