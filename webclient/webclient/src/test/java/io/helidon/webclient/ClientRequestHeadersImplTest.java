package io.helidon.webclient;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import io.helidon.common.CollectionsHelper;
import io.helidon.common.http.Http;
import io.helidon.common.http.MediaType;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * TODO Javadoc
 */
public class ClientRequestHeadersImplTest {

    private ClientRequestHeaders clientRequestHeaders;

    @BeforeEach
    public void beforeEach() {
        clientRequestHeaders = new ClientRequestHeadersImpl();
    }

    @Test
    public void testAcceptedTypes() {
        List<MediaType> expectedTypes = CollectionsHelper.listOf(MediaType.TEXT_PLAIN, MediaType.APPLICATION_JSON);

        clientRequestHeaders.addAccept(MediaType.TEXT_PLAIN);
        clientRequestHeaders.add(Http.Header.ACCEPT, MediaType.APPLICATION_JSON.toString());

        assertThat(clientRequestHeaders.acceptedTypes(), is(expectedTypes));
    }

    @Test
    public void testContentType() {
        assertThat(clientRequestHeaders.contentType(), is(MediaType.WILDCARD));

        clientRequestHeaders.add(Http.Header.CONTENT_TYPE, MediaType.APPLICATION_XML.toString());
        assertThat(clientRequestHeaders.contentType(), is(MediaType.APPLICATION_XML));

        clientRequestHeaders.contentType(MediaType.APPLICATION_JSON);
        assertThat(clientRequestHeaders.contentType(), is(MediaType.APPLICATION_JSON));
    }

    @Test
    public void testContentLength() {
        long contentLengthTemplate = 123;

        assertThat(clientRequestHeaders.contentLength(), is(Optional.empty()));

        clientRequestHeaders.contentLength(contentLengthTemplate);
        assertThat(clientRequestHeaders.contentLength(), is(Optional.of(contentLengthTemplate)));
    }

    @Test
    public void testIfModifiedSince() {
        String template = "Mon, 30 Nov 2015 22:45:59 GMT";
        ZonedDateTime zonedDateTemplate =
                ZonedDateTime.of(2015, 11, 30, 22, 45, 59, 0, ZoneId.of("GMT"));
        ZonedDateTime ifModifiedSince =
                ZonedDateTime.of(2015, 11, 30, 23, 45, 59, 1234, ZoneId.of("UTC+1"));

        assertThat(clientRequestHeaders.ifModifiedSince(), is(Optional.empty()));

        clientRequestHeaders.ifModifiedSince(ifModifiedSince);

        assertThat(clientRequestHeaders.first(Http.Header.IF_MODIFIED_SINCE), is(Optional.of(template)));
        assertThat(clientRequestHeaders.ifModifiedSince(), is(Optional.of(zonedDateTemplate)));
    }

    @Test
    public void testIfNoneMatch() {
        //TODO https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match
        //EDIT: prima metoda vraci unquoted, jinak s
//        List<String> noneMatchTemplate = CollectionsHelper.listOf("test", "test2");
//        //List<String> noneMatchTemplate = CollectionsHelper.listOf("\"test\"", "test2");
//
//        assertThat(clientRequestHeaders.ifNoneMatch(), is(Collections.emptyList()));
//
//        clientRequestHeaders.ifNoneMatch(noneMatchTemplate.toArray(new String[0]));
//        assertThat(clientRequestHeaders.ifNoneMatch(), is(noneMatchTemplate));
    }


}
