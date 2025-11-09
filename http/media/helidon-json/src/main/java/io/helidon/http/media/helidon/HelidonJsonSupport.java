package io.helidon.http.media.helidon;

import java.util.function.Consumer;

import io.helidon.builder.api.RuntimeType;
import io.helidon.common.GenericType;
import io.helidon.common.config.Config;
import io.helidon.common.media.type.MediaTypes;
import io.helidon.http.HeaderNames;
import io.helidon.http.Headers;
import io.helidon.http.HttpMediaType;
import io.helidon.http.WritableHeaders;
import io.helidon.http.media.EntityReader;
import io.helidon.http.media.EntityWriter;
import io.helidon.http.media.MediaSupport;
import io.helidon.json.binding.JsonBinding;

import static io.helidon.http.HeaderValues.CONTENT_TYPE_JSON;

@SuppressWarnings({"rawtypes", "unchecked"})
@RuntimeType.PrototypedBy(HelidonJsonSupportConfig.class)
public class HelidonJsonSupport implements MediaSupport, RuntimeType.Api<HelidonJsonSupportConfig> {

    private final String name;
    private final HelidonJsonSupportConfig supportConfig;
    private final JsonBinding jsonBinding;

    private final HelidonJsonReader reader;
    private final HelidonJsonWriter writer;

    private HelidonJsonSupport(HelidonJsonSupportConfig supportConfig) {
        this.name = supportConfig.name();
        this.supportConfig = supportConfig;
        this.jsonBinding = supportConfig.jsonBinding();
        
        this.reader = new HelidonJsonReader(jsonBinding);
        this.writer = new HelidonJsonWriter(jsonBinding);
    }

    public static MediaSupport create(Config config, String name) {
        return builder()
                .name(name)
                .config(config)
                .build();
    }

    public static HelidonJsonSupport create(HelidonJsonSupportConfig config) {
        return new HelidonJsonSupport(config);
    }

    public static HelidonJsonSupport create(Consumer<HelidonJsonSupportConfig.Builder> consumer) {
        return builder().update(consumer).build();
    }

    public static HelidonJsonSupportConfig.Builder builder() {
        return HelidonJsonSupportConfig.builder();
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String type() {
        return "helidon-json";
    }

    @Override
    public HelidonJsonSupportConfig prototype() {
        return supportConfig;
    }

    <T> EntityReader<T> reader() {
        return reader;
    }

    <T> EntityWriter<T> writer() {
        return writer;
    }

    @Override
    public <T> ReaderResponse<T> reader(GenericType<T> type, Headers requestHeaders) {
        if (requestHeaders.contentType()
                .map(it -> it.test(MediaTypes.APPLICATION_JSON))
                .orElse(true)) {
            return new ReaderResponse<>(SupportLevel.COMPATIBLE, this::reader);
        }

        return ReaderResponse.unsupported();
    }

    @Override
    public <T> WriterResponse<T> writer(GenericType<T> type,
                                        Headers requestHeaders,
                                        WritableHeaders<?> responseHeaders) {
        // check if accepted
        for (HttpMediaType acceptedType : requestHeaders.acceptedTypes()) {
            if (acceptedType.test(MediaTypes.APPLICATION_JSON)) {
                return new WriterResponse<>(SupportLevel.COMPATIBLE, this::writer);
            }
        }

        if (requestHeaders.acceptedTypes().isEmpty()) {
            return new WriterResponse<>(SupportLevel.COMPATIBLE, this::writer);
        }

        return WriterResponse.unsupported();
    }

    @Override
    public <T> ReaderResponse<T> reader(GenericType<T> type,
                                        Headers requestHeaders,
                                        Headers responseHeaders) {
        // check if accepted
        for (HttpMediaType acceptedType : requestHeaders.acceptedTypes()) {
            if (acceptedType.test(MediaTypes.APPLICATION_JSON) || acceptedType.mediaType().isWildcardType()) {
                return new ReaderResponse<>(SupportLevel.COMPATIBLE, this::reader);
            }
        }

        if (requestHeaders.acceptedTypes().isEmpty()) {
            return new ReaderResponse<>(SupportLevel.COMPATIBLE, this::reader);
        }

        return ReaderResponse.unsupported();
    }

    @Override
    public <T> WriterResponse<T> writer(GenericType<T> type, WritableHeaders<?> requestHeaders) {
        if (requestHeaders.contains(HeaderNames.CONTENT_TYPE)) {
            if (requestHeaders.contains(CONTENT_TYPE_JSON)) {
                return new WriterResponse<>(SupportLevel.COMPATIBLE, this::writer);
            }
        } else {
            return new WriterResponse<>(SupportLevel.SUPPORTED, this::writer);
        }
        return WriterResponse.unsupported();
    }
}
