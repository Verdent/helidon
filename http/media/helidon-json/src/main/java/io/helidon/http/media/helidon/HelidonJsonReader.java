package io.helidon.http.media.helidon;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.Charset;
import java.util.Optional;

import io.helidon.common.GenericType;
import io.helidon.http.Headers;
import io.helidon.http.HttpMediaType;
import io.helidon.http.media.EntityReader;
import io.helidon.json.binding.JsonBinding;

class HelidonJsonReader<T> implements EntityReader<T> {
    private final JsonBinding jsonBinding;

    HelidonJsonReader(JsonBinding jsonBinding) {
        this.jsonBinding = jsonBinding;
    }

    @Override
    public T read(GenericType<T> type, InputStream stream, Headers headers) {
        Optional<InputStreamReader> reader = contentTypeCharset(headers)
                .map(charset -> new InputStreamReader(stream, charset));
        if (reader.isPresent()) {
            return read(type, reader.get());
        }
        return read(type, stream);
    }

    @Override
    public T read(GenericType<T> type, InputStream stream, Headers requestHeaders, Headers responseHeaders) {
        Optional<InputStreamReader> reader = contentTypeCharset(responseHeaders)
                .map(charset -> new InputStreamReader(stream, charset));
        if (reader.isPresent()) {
            return read(type, reader.get());
        }
        return read(type, stream);
    }

    private T read(GenericType<T> type, InputStream in) {
        try (in) {
            return jsonBinding.deserialize(in, type);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private T read(GenericType<T> type, Reader reader) {
        try (reader) {
            return jsonBinding.deserialize(reader, type);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private Optional<Charset> contentTypeCharset(Headers headers) {
        return headers.contentType()
                .flatMap(HttpMediaType::charset)
                .map(Charset::forName);
    }
}
