package io.helidon.json;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

final class JsonStreamParser extends ArrayJsonParser {

    private static final int DEFAULT_BUFFER_SIZE = 8192;

    private final int bufferSize;
    private InputStream inputStream;
    private boolean finished;
    private boolean bufferingJsonValue;
    private int jsonValueStart;

    JsonStreamParser(InputStream inputStream, int bufferSize) {
        this.bufferSize = bufferSize;
        this.inputStream = inputStream;
        currentIndex = 0;
        buffer = new byte[bufferSize];
        try {
            bufferLength = inputStream.read(buffer);
            finished = bufferLength != bufferSize;
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
        if (!finished && currentIndex + 1 >= bufferLength) {
            fetchData();
        }
        return super.hasNext();
    }

    @Override
    public byte readNextByte() {
        if (currentIndex + 1 == bufferLength) {
            if (finished) {
                throw new JsonException("Incomplete JSON data.");
            }
            readMoreData();
        }
        return buffer[++currentIndex];
    }

    private void readMoreData() {
        try {
            if (bufferingJsonValue) {
                if (jsonValueStart > 0) {
                    //There is still some free space in this current buffer to be used
                    currentIndex = bufferLength - jsonValueStart; //index has to be at the very end of the value
                    System.arraycopy(buffer, jsonValueStart, buffer, 0, bufferLength - jsonValueStart);
                    jsonValueStart = 0;
                    int lastRead = inputStream.read(buffer, currentIndex, bufferLength - currentIndex);
                    finished = lastRead != (bufferLength - currentIndex);
                } else {
                    bufferLength = buffer.length + bufferSize;
                    currentIndex = buffer.length;
                    byte[] tmp = new byte[bufferLength];
                    System.arraycopy(buffer, 0, tmp, 0, buffer.length);
                    int lastRead = inputStream.read(tmp, currentIndex, bufferLength - currentIndex);
                    finished = lastRead != bufferSize;
                    buffer = tmp;
                }
            } else {
                //Some parsing methods need to detect one byte after their value to see, if they are supposed to end
                //When end is detected, they go 1 byte back to be on the right state -> end of the value
                //if the value ends at the end of the buffer, and we would not keep the last byte from the previous
                //we would risk to getting out of the bounds of the array buffer
                buffer[0] = buffer[currentIndex - 1];
                bufferLength = inputStream.read(buffer, 1, buffer.length - 1);
                bufferLength += 1;
                finished = bufferLength != bufferSize;
                currentIndex = 0;
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void reset(InputStream is) {
        bufferingJsonValue = false;
        inputStream = is;
        currentIndex = 0;
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
    public JsonNumber readJsonNumber() {
        bufferingJsonValue = true;
        jsonValueStart = currentIndex;
        skipNumber();
        int length = currentIndex -  jsonValueStart;
        byte[] numberBytes = new byte[length];
        System.arraycopy(buffer, jsonValueStart, numberBytes, 0, length);
        bufferingJsonValue = false;
        return JsonNumber.create(numberBytes, 0, length);
    }

    @Override
    void skipNumber() {
        byte b;
        int index;
        while (true) {
            for (index = this.currentIndex; index < this.bufferLength; index++) {
                b = this.buffer[index];
                //we do not need to validate whether this is a valid number since we are not processing it.
                //simply skip until you find any valid character after the number
                if (b == ',' || b == '}' || b == ']' || b == ' ' || b == '\n' || b == '\t') {
                    this.currentIndex = index;
                    return;
                }
            }
            if (!finished) {
                readMoreData();
            } else {
                this.currentIndex = index;
                break;
            }
        }
    }

    @Override
    public JsonString readJsonString() {
        bufferingJsonValue = true;
        jsonValueStart = currentIndex;
        skipStringValue();
        int length = currentIndex - jsonValueStart;
        byte[] stringBytes = new byte[length];
        System.arraycopy(buffer, jsonValueStart, stringBytes, 0, length);
        bufferingJsonValue = false;
        return JsonString.create(stringBytes, 0, length);
    }

    @Override
    void skipStringValue() {
        if (currentByte() == '"') {
            jsonValueStart = ++this.currentIndex;
        }
        boolean isEscaped = false;
        byte b;
        while (true) {
            for (int index = this.currentIndex; index < this.bufferLength; index++) {
                b = this.buffer[index];
                if (b == '\\') {
                    isEscaped = !isEscaped;
                } else if (b == '"' && !isEscaped) {
                    this.currentIndex = index;
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
