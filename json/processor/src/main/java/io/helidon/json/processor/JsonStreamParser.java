package io.helidon.json.processor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

final class JsonStreamParser extends AbstractJsonParser {

    private static final int DEFAULT_BUFFER_SIZE = 8192;
    private static final int DEFAULT_KEEP_AMOUNT = 2;

    private final int bufferSize;
    private InputStream inputStream;
    private boolean finished;
    private boolean bufferingJsonValue;
    private boolean doNotReuseBuffer = false;

    JsonStreamParser(InputStream inputStream, int bufferSize) {
        this.bufferSize = bufferSize;
        this.inputStream = inputStream;
        currentIndex = -1;
        buffer = new byte[bufferSize];
        try {
            bufferLength = inputStream.read(buffer);
            finished = bufferLength != DEFAULT_BUFFER_SIZE;
        } catch (IOException e) {
            throw new JsonException("Error occurred while reading JSON to the buffer.", e);
        }
    }

    JsonStreamParser(InputStream inputStream) {
        this(inputStream, DEFAULT_BUFFER_SIZE);
    }

    JsonStreamParser() {
        this(new ByteArrayInputStream(new byte[0]), DEFAULT_BUFFER_SIZE);
    }

    @Override
    public boolean hasNext() {
        return !finished || super.hasNext();
    }

    @Override
    public byte readNextByte() {
        if (++currentIndex == bufferLength) {
            if (finished) {
                throw new JsonException("Incomplete JSON data.");
            }
            readMoreData();
        }
        return buffer[currentIndex];
    }

    private void readMoreData() {
        try {
            if (bufferingJsonValue) {
                bufferLength = buffer.length + bufferSize;
                byte[] tmp = new byte[bufferLength];
                System.arraycopy(buffer, 0, tmp, 0, buffer.length);
                int lastRead = inputStream.read(tmp, buffer.length, bufferSize);
                finished = lastRead != bufferSize;
                buffer = tmp;
            } else {
                if (doNotReuseBuffer) {
                    buffer = new byte[bufferSize];
                }
                System.arraycopy(buffer, bufferLength - DEFAULT_KEEP_AMOUNT, buffer, 0, DEFAULT_KEEP_AMOUNT);
                bufferLength = inputStream.read(buffer, DEFAULT_KEEP_AMOUNT, buffer.length - DEFAULT_KEEP_AMOUNT);
                finished = (bufferLength + DEFAULT_KEEP_AMOUNT) != bufferSize;
                currentIndex = DEFAULT_KEEP_AMOUNT - 1;
                bufferLength += DEFAULT_KEEP_AMOUNT;
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void reset(InputStream is) {
        inputStream = is;
        currentIndex = -1;
        try {
            bufferLength = inputStream.read(buffer);
            finished = bufferLength != DEFAULT_BUFFER_SIZE;
        } catch (IOException e) {
            throw new JsonException("Error occurred while reading JSON to the buffer.", e);
        }
    }

    @Override
    void ensure(int amount) {
        if (currentIndex + amount >= bufferLength) {
            fetchData();
            if (currentIndex + amount >= bufferLength) {
                throw new JsonException("There is not enough data to be fetched. Incomplete JSON.");
            }
        }
    }

    @Override
    void fetchData() {
        if (finished) {
            throw new JsonException("There are no more data to fetch. Incomplete JSON.");
        }
        readMoreData();
    }

    @Override
    public int readStringAsHash() {
        if (currentByte() != '"') {
            throw new JsonException("This is supported only for Strings.");
        } else if (!hasNext()) {
            throw new JsonException("Incomplete JSON.");
        }
        //Based on recommended offset basis and prime values.
        int fnv1aHash = FNV_OFFSET_BASIS;
        byte b;
        while (true) {
            b = readNextByte();
            if (b == '"') {
                return fnv1aHash;
            }
            fnv1aHash ^= (b & 0xFF);
            fnv1aHash *= FNV_PRIME;
        }
    }

    @Override
    void skipStringValue() {
        doNotReuseBuffer = true;
        bufferingJsonValue = true;
        this.currentIndex++;
        boolean isEscaped = false;
        byte b;
        while (true) {
            for (int index = this.currentIndex; index < this.bufferLength; index++) {
                b = this.buffer[index];
                if (b == '\\') {
                    isEscaped = !isEscaped;
                } else if (b == '"' && !isEscaped) {
                    this.currentIndex = index;
                    bufferingJsonValue = false;
                    return;
                } else {
                    isEscaped = false;
                }
            }
            if (finished) {
                throw new JsonException("Incomplete JSON.");
            }
            readMoreData();
        }
    }

    @Override
    public byte nextToken() {
        //Optimization for faster reading data without a space
        //No loop is used.
        byte b = readNextByte();
        if (!WHITESPACE_CHARS[b & 0xFF]) {
            return b;
        }
        //If since space or why character was used between tokens, we should still try to optimize
        b = readNextByte();
        if (!WHITESPACE_CHARS[b & 0xFF]) {
            return b;
        }
        //We dont know how many spaces, new lines etc is there present, lets start looping
        while (true) {
            b = readNextByte();
            if (!WHITESPACE_CHARS[b & 0xFF]) {
                return b;
            }
        }
    }
}
