package io.helidon.json.processor;

import java.io.IOException;
import java.io.InputStream;

final class JsonStreamParser extends JsonParserImpl {

    private static final int DEFAULT_BUFFER_SIZE = 8192;
    
    private InputStream inputStream;
    private boolean finished;

    public JsonStreamParser() {
        super(new byte[DEFAULT_BUFFER_SIZE]);
    }

    public JsonStreamParser(InputStream inputStream) {
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
    boolean hasNext() {
        return !finished || super.hasNext();
    }

    @Override
    public byte readNextByte() {
        if (!finished && currentIndex + 25 < bufferLength) {
            try {
                System.arraycopy(buffer, currentIndex - 24, buffer, 0, 50);
                bufferLength = inputStream.read(buffer, 50, buffer.length - 50);
                finished = bufferLength != DEFAULT_BUFFER_SIZE;
                currentIndex = 0;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return super.readNextByte();
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
}
