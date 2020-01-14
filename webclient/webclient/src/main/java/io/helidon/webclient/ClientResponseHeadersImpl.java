package io.helidon.webclient;

import java.net.URI;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import io.helidon.common.http.Http;
import io.helidon.common.http.MediaType;
import io.helidon.common.http.ReadOnlyParameters;
import io.helidon.common.http.SetCookie;

/**
 * Implementation of {@link ClientResponseHeaders}.
 */
class ClientResponseHeadersImpl extends ReadOnlyParameters implements ClientResponseHeaders {

    //EDIT: jinak
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss z")
            .withLocale(Locale.US)
            .withZone(ZoneId.of("GMT"));

    //EDIT: dalsi metody

    ClientResponseHeadersImpl(Map<String, List<String>> headers) {
        super(headers);
    }

    @Override
    public List<SetCookie> setCookies() {
//        return all(Http.Header.SET_COOKIE).stream()
//                .map(s -> s.s);
        System.out.println();
        return null;
    }

    @Override
    public Optional<URI> location() {
        return first(Http.Header.LOCATION).map(URI::create);
    }

    @Override
    public Optional<ZonedDateTime> lastModified() {
        return first(Http.Header.LAST_MODIFIED).map(date -> ZonedDateTime.parse(date, FORMATTER));
    }

    @Override
    public Optional<MediaType> contentType() {
        return first(Http.Header.CONTENT_TYPE).map(MediaType::parse);
    }

}
