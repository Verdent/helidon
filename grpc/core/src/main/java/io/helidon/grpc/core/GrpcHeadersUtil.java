/*
 * Copyright (c) 2024, 2026 Oracle and/or its affiliates.
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

package io.helidon.grpc.core;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

import io.helidon.http.Header;
import io.helidon.http.HeaderNames;
import io.helidon.http.Headers;
import io.helidon.http.WritableHeaders;
import io.helidon.http.http2.Http2Headers;

import io.grpc.Metadata;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Utility class to map HTTP/2 headers to Metadata.
 */
public class GrpcHeadersUtil {
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private GrpcHeadersUtil() {
    }

    /**
     * Updates headers with metadata.
     *
     * @param headers the headers to update
     * @param metadata the metadata
     */
    public static void updateHeaders(WritableHeaders<?> headers, Metadata metadata) {
        Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
        metadata.keys().forEach(name -> {
            if (name.endsWith(Metadata.BINARY_HEADER_SUFFIX)) {
                Metadata.Key<byte[]> key = Metadata.Key.of(name, Metadata.BINARY_BYTE_MARSHALLER);
                Iterable<byte[]> binary = metadata.getAll(key);
                if (binary != null) {
                    binary.forEach(value -> headers.add(HeaderNames.create(name),
                                                         new String(encoder.encode(value), US_ASCII)));
                }
            } else {
                Metadata.Key<String> key = Metadata.Key.of(name, Metadata.ASCII_STRING_MARSHALLER);
                Iterable<String> ascii = metadata.getAll(key);
                if (ascii != null) {
                    ascii.forEach(v -> headers.add(HeaderNames.create(name), v));
                }
            }
        });
    }

    /**
     * Converts a set of HTTP/2 headers into a Metadata instance.
     *
     * @param headers the headers to convert
     * @return the new metadata
     */
    public static Metadata toMetadata(Http2Headers headers) {
        return toMetadata(headers.httpHeaders());
    }

    /**
     * Converts a set of headers into a Metadata instance.
     *
     * @param headers the headers to convert
     * @return the new metadata
     */
    public static Metadata toMetadata(Headers headers) {
        Base64.Decoder decoder = Base64.getDecoder();
        Metadata metadata = new Metadata();
        headers.forEach(header -> updateMetadata(metadata, header, decoder));
        return metadata;
    }

    /**
     * Encodes a gRPC status message header value.
     *
     * @param message message to encode
     * @return encoded header value
     */
    public static String encodeMessage(String message) {
        byte[] bytes = message.getBytes(UTF_8);
        StringBuilder builder = new StringBuilder(bytes.length);
        for (byte aByte : bytes) {
            int value = aByte & 0xFF;
            if (isGrpcMessageCharacter(value)) {
                builder.append((char) value);
            } else {
                builder.append('%')
                        .append(HEX[value >>> 4])
                        .append(HEX[value & 0x0F]);
            }
        }
        return builder.toString();
    }

    /**
     * Decodes a gRPC status message header value.
     *
     * @param message encoded header value
     * @return decoded message
     */
    public static String decodeMessage(String message) {
        if (message.indexOf('%') < 0) {
            return message;
        }

        ByteArrayOutputStream bytes = new ByteArrayOutputStream(message.length());

        for (int i = 0; i < message.length();) {
            char current = message.charAt(i);
            if (current == '%' && (i + 2) < message.length()) {
                int high = hexValue(message.charAt(i + 1));
                int low = hexValue(message.charAt(i + 2));
                if (high >= 0 && low >= 0) {
                    bytes.write((high << 4) + low);
                    i += 3;
                    continue;
                }
            }
            if (current == '%') {
                bytes.write('%');
                i++;
                continue;
            }

            int nextPercent = message.indexOf('%', i);
            int end = nextPercent < 0 ? message.length() : nextPercent;
            byte[] raw = message.substring(i, end).getBytes(UTF_8);
            bytes.write(raw, 0, raw.length);
            i = end;
        }

        return bytes.toString(UTF_8);
    }

    private static void updateMetadata(Metadata metadata, Header header, Base64.Decoder decoder) {
        String name = header.name();
        if (name.endsWith(Metadata.BINARY_HEADER_SUFFIX)) {
            Metadata.Key<byte[]> key = Metadata.Key.of(name, Metadata.BINARY_BYTE_MARSHALLER);
            header.allValues().forEach(value -> {
                for (String item : value.split(",")) {
                    String binary = item.trim();
                    if (!binary.isEmpty()) {
                        metadata.put(key, decoder.decode(binary));
                    }
                }
            });
            return;
        }

        Metadata.Key<String> key = Metadata.Key.of(name, Metadata.ASCII_STRING_MARSHALLER);
        header.allValues().forEach(value -> metadata.put(key, value));
    }

    private static boolean isGrpcMessageCharacter(int value) {
        return (value >= 0x20 && value <= 0x24) || (value >= 0x26 && value <= 0x7E);
    }

    private static int hexValue(char value) {
        if (value >= '0' && value <= '9') {
            return value - '0';
        }
        if (value >= 'A' && value <= 'F') {
            return 10 + (value - 'A');
        }
        if (value >= 'a' && value <= 'f') {
            return 10 + (value - 'a');
        }
        return -1;
    }
}
