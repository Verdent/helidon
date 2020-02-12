package io.helidon.webclient;

import java.net.URI;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import io.helidon.common.http.Http;
import io.helidon.common.http.MediaType;
import io.helidon.common.http.ReadOnlyParameters;
import io.helidon.common.http.SetCookie;

/**
 * Implementation of {@link ClientResponseHeaders}.
 */
class ClientResponseHeadersImpl extends ReadOnlyParameters implements ClientResponseHeaders {

    ClientResponseHeadersImpl(Map<String, List<String>> headers) {
        super(headers);
    }

    @Override
    public List<SetCookie> setCookies() {
        return all(Http.Header.SET_COOKIE)
                .stream()
                .map(SetCookie::parse)
                .collect(Collectors.toList());
    }

    @Override
    public Optional<URI> location() {
        return first(Http.Header.LOCATION).map(URI::create);
    }

    @Override
    public Optional<ZonedDateTime> lastModified() {
        return first(Http.Header.LAST_MODIFIED).map(Http.DateTime::parse);
    }

    @Override
    public Optional<ZonedDateTime> expires() {
        return first(Http.Header.EXPIRES).map(Http.DateTime::parse);
    }

    @Override
    public Optional<ZonedDateTime> date() {
        return first(Http.Header.DATE).map(Http.DateTime::parse);
    }

    @Override
    public Optional<MediaType> contentType() {
        return first(Http.Header.CONTENT_TYPE).map(MediaType::parse);
    }

    @Override
    public Optional<String> etag() {
        return first(Http.Header.ETAG).map(this::unquoteETag);
    }

    private String unquoteETag(String etag) {
        if (etag == null || etag.isEmpty()) {
            return etag;
        }
        if (etag.startsWith("W/") || etag.startsWith("w/")) {
            etag = etag.substring(2);
        }
        if (etag.startsWith("\"") && etag.endsWith("\"")) {
            etag = etag.substring(1, etag.length() - 1);
        }
        return etag;
    }

}
