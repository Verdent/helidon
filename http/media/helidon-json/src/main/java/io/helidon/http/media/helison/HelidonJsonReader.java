package io.helidon.http.media.helison;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

import io.helidon.common.GenericType;
import io.helidon.http.Headers;
import io.helidon.http.media.EntityReader;
import io.helidon.json.binding.JsonBinding;

class HelidonJsonReader<T> implements EntityReader<T> {
    private final JsonBinding jsonBinding;

    HelidonJsonReader(JsonBinding jsonBinding) {
        this.jsonBinding = jsonBinding;
    }

    @Override
    public T read(GenericType<T> type, InputStream stream, Headers headers) {
        return read(type, stream);
    }

    @Override
    public T read(GenericType<T> type, InputStream stream, Headers requestHeaders, Headers responseHeaders) {
        return read(type, stream);
    }

    private T read(GenericType<T> type, InputStream in) {
        //Charset is not supported yet
        try (in) {
            return jsonBinding.deserialize(in, type);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
