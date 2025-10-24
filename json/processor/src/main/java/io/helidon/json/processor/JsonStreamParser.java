package io.helidon.json.processor;

import java.io.IOException;
import java.io.InputStream;

final class JsonStreamParser extends AbstractJsonParser {

    private static final int DEFAULT_BUFFER_SIZE = 8192;
    private static final int DEFAULT_KEEP_AMOUNT = 20;

    private final int bufferSize;
    private InputStream inputStream;
    private boolean finished;

    JsonStreamParser() {
        super(new byte[DEFAULT_BUFFER_SIZE]);
        bufferSize = DEFAULT_BUFFER_SIZE;
    }

    JsonStreamParser(int bufferSize) {
        super(new byte[bufferSize]);
        this.bufferSize = bufferSize;
    }

    JsonStreamParser(InputStream inputStream) {
        bufferSize = DEFAULT_BUFFER_SIZE;
        this.inputStream = inputStream;
        currentIndex = -1;
        buffer = new byte[DEFAULT_BUFFER_SIZE];
        try {
            bufferLength = inputStream.read(buffer);
            finished = bufferLength != DEFAULT_BUFFER_SIZE;
        } catch (IOException e) {
            throw new JsonException("Error occurred while reading JSON to the buffer.", e);
        }
    }

    @Override
    public boolean hasNext() {
        return !finished || super.hasNext();
    }

    @Override
    public byte readNextByte() {
        if (currentIndex + 1 == bufferLength) {
            if (finished) {
                throw new JsonException("Incomplete JSON data.");
            }
            readMoreData();
        }
        return super.readNextByte();
    }

    private void readMoreData() {
        try {
            if (doNotReuseBuffer) {
                buffer = new byte[bufferSize];
            }
            System.arraycopy(buffer, bufferLength - DEFAULT_KEEP_AMOUNT, buffer, 0, DEFAULT_KEEP_AMOUNT);
            bufferLength = inputStream.read(buffer, DEFAULT_KEEP_AMOUNT, buffer.length - DEFAULT_KEEP_AMOUNT);
            finished = (bufferLength + DEFAULT_KEEP_AMOUNT) != bufferSize;
            currentIndex = DEFAULT_KEEP_AMOUNT - 1;
            bufferLength += DEFAULT_KEEP_AMOUNT;
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
                throw new JsonException("There are no more data to fetch. Incomplete JSON.");
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
    public byte nextToken() {
        //Optimization for faster reading data without a space
        //No loop is used.
        byte b = readNextByte();
        switch (b) {
        case '\r':
        case '\t':
        case '\n':
        case ' ':
            break;
        default:
            return b;
        }
        //If since space or why character was used between tokens, we should still try to optimize
        b = readNextByte();
        switch (b) {
        case '\r':
        case '\t':
        case '\n':
        case ' ':
            break;
        default:
            return b;
        }
        //We dont know how many spaces, new lines etc is there present, lets start looping
        while (true) {
            b = readNextByte();
            switch (b) {
            case '\r':
            case '\t':
            case '\n':
            case ' ':
                continue;
            default:
                return b;
            }
        }
    }
}
