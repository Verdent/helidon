/*
 * Copyright (c) 2025 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.json;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

final class JsonStreamParser extends ArrayJsonParser {

    private static final int DEFAULT_BUFFER_SIZE = 512;

    private final int bufferSize;
    private final InputStream inputStream;
    private boolean finished;
    private boolean bufferingJsonValue;
    private int jsonValueStart;

    JsonStreamParser(InputStream inputStream, int bufferSize) {
        this.bufferSize = bufferSize;
        this.inputStream = inputStream;
        currentIndex = 0;
        buffer = new byte[bufferSize];
        try {
            int read = inputStream.read(buffer);
            bufferLength = (read == -1 ? 0 : read);
            finished = (read == -1);
        } catch (IOException e) {
            throw new RuntimeException("Error occurred while reading JSON to the buffer", e);
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
                throw createException("Incomplete JSON data");
            }
            readMoreData();
        }
        return buffer[++currentIndex];
    }

    @Override
    void ensure(int amount) {
        if (currentIndex + amount >= bufferLength) {
            fetchData();
            super.ensure(amount);
        }
    }

    void fetchData() {
        if (finished) {
            throw createException("There are no more data to fetch. Incomplete JSON");
        }
        readMoreData();
    }

    @Override
    public int readStringAsHash() {
        if (currentByte() != '"') {
            throw createException("Hash calculation is intended only for String values");
        } else if (!hasNext()) {
            throw createException("Incomplete JSON");
        }
        //Based on recommended offset basis and prime values.
//        int fnv1aHash = FNV_OFFSET_BASIS;
//        byte b;
//        while (true) {
//            b = readNextByte();
//            if (b == '"') {
//                return fnv1aHash;
//            }
//            fnv1aHash ^= (b & 0xFF);
//            fnv1aHash *= FNV_PRIME;
//        }


        int i = currentIndex + 1;
        while (true) {
            //Based on recommended offset basis and prime values.
            int fnv1aHash = FNV_OFFSET_BASIS;
            byte b;
            while (i < bufferLength) {
                b = buffer[i++];
                if (b == '"') {
                    currentIndex = i - 1;
                    return fnv1aHash;
                }
                fnv1aHash ^= (b & 0xFF);
                fnv1aHash *= FNV_PRIME;
            }
            fetchData();
            i = currentIndex;
        }
    }

    @Override
    public JsonNumber readJsonNumber() {
        bufferingJsonValue = true;
        jsonValueStart = currentIndex;
        skipNumber();
        int length = currentIndex - jsonValueStart;
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
                //simply skip until you find any non-numeric bound character
                if (!VALID_NUMBER_PARTS[b]) {
                    this.currentIndex = index - 1;
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
        skipString();
        int length = currentIndex - jsonValueStart;
        byte[] stringBytes = new byte[length];
        System.arraycopy(buffer, jsonValueStart, stringBytes, 0, length);
        bufferingJsonValue = false;
        return JsonString.create(stringBytes, 0, length);
    }

    @Override
    void skipString() {
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
                throw createException("Unexpected end of string. Incomplete JSON or incorrect use of the skip method");
            }
            readMoreData();
        }
    }

    @Override
    public String readString() {
        if (checkNull()) {
            return null;
        } else if (currentByte() != '"') {
            throw createException("Expected start of string", currentByte());
        }
        int index = ++currentIndex;
        int readableBytes = bufferLength - currentIndex;
        int firstRun = Math.min(stringBufferLength, readableBytes);
        byte b;
        int stringBuffIndex = 0;
        for (;stringBuffIndex < firstRun; stringBuffIndex++) {
            b = this.buffer[index++];
            if (b == '"') {
                currentIndex = --index;
                return new String(stringBuffer, 0, stringBuffIndex);
            } else if ((b ^ '\\') < 1) { //Either \ or UTF-8 byte detected
                //Either escaped sequence or multibyte detected
                currentIndex = --index;
                break;
            }
            stringBuffer[stringBuffIndex] = (char) b;
        }

        if (stringBuffIndex == stringBufferLength) {
            increaseStringBuffer();
        }
//        currentIndex++;
//        int stringBuffIndex = 0;
//        byte b;
//        for (; currentIndex < this.bufferLength && stringBuffIndex < stringBufferLength; currentIndex++, stringBuffIndex++) {
//            b = this.buffer[currentIndex];
//            if (b == '"') {
//                return new String(stringBuffer, 0, stringBuffIndex);
//            } else if ((b ^ '\\') < 1) {
//                //Either escaped sequence or multibyte detected
//                currentIndex--;
//                break;
//            }
//            stringBuffer[stringBuffIndex] = (char) b;
//        }
//
//        if (stringBuffIndex == stringBufferLength) {
//            increaseStringBuffer();
//        }
        if (currentIndex == this.bufferLength) {
            if (finished) {
                throw createException("End of the string expected. Incomplete JSON");
            }
            readMoreData();
        }

        while (true) {
            while (currentIndex + 1 < this.bufferLength) {
                b = this.buffer[++currentIndex];
                if (b == '\\') {
                    stringBuffer[stringBuffIndex++] = processEscapedSequence();
                } else if (b == '"') {
                    return new String(stringBuffer, 0, stringBuffIndex);
                } else if ((b & 0x80) == 0) {
                    stringBuffer[stringBuffIndex++] = (char) b;
                } else {
                    // Decode UTF-8 multibyte sequence starting with this byte
                    stringBuffIndex = decodeUtf8(stringBuffIndex, b);
                }
                if (stringBuffIndex == stringBufferLength) {
                    increaseStringBuffer();
                }
            }
            if (finished) {
                throw createException("End of the string expected. Incomplete JSON");
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

    /**
     * Reads more data from the input stream into the buffer, handling buffering for JSON values that span multiple reads.
     * There are two modes: bufferingJsonValue (for values like strings or numbers) and non-buffering (for structural parsing).
     */
    private void readMoreData() {
        try {
            if (bufferingJsonValue) {
                // When buffering a JSON value (e.g., string or number), we need to preserve the value across reads
                if (jsonValueStart > 0) {
                    // Move the partial value to the beginning of the buffer to make room for more data
                    int valueLen = bufferLength - jsonValueStart;
                    currentIndex = valueLen; // Position at end of moved value
                    System.arraycopy(buffer, jsonValueStart, buffer, 0, valueLen);
                    jsonValueStart = 0; // Reset start position
                    int lastRead = inputStream.read(buffer, currentIndex, buffer.length - currentIndex);
                    if (lastRead == -1) {
                        finished = true;
                        bufferLength = currentIndex; // Only the moved value remains
                    } else {
                        bufferLength = currentIndex + lastRead;
                        finished = false;
                    }
                } else {
                    // Buffer is full with the value, need to expand
                    int newCap = buffer.length + bufferSize;
                    byte[] tmp = new byte[newCap];
                    System.arraycopy(buffer, 0, tmp, 0, bufferLength); // Copy existing data
                    currentIndex = bufferLength;
                    int lastRead = inputStream.read(tmp, currentIndex, newCap - currentIndex);
                    buffer = tmp; // Replace buffer
                    if (lastRead == -1) {
                        finished = true;
                        bufferLength = currentIndex;
                    } else {
                        bufferLength = currentIndex + lastRead;
                        finished = false;
                    }
                }
            } else {
                // For structural parsing, keep one byte of look-ahead to detect value boundaries
                // Preserve the byte before currentIndex to allow backtracking
                buffer[0] = buffer[currentIndex - 1];
                int lastRead = inputStream.read(buffer, 1, buffer.length - 1); // Read into buffer[1..]
                if (lastRead == -1) {
                    finished = true;
                    bufferLength = 1; // Only the preserved byte
                } else {
                    bufferLength = lastRead + 1;
                    finished = false;
                }
                currentIndex = 0; // Reset to beginning
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
