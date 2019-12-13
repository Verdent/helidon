package io.helidon.webclient;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.helidon.common.http.Http;
import io.helidon.common.http.MediaType;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * TODO Javadoc
 */
public class ClientRequestHeadersImplTest {

    private static final ClientRequestHeaders CLIENT_REQUEST_HEADERS;

    static {
        CLIENT_REQUEST_HEADERS = new ClientRequestHeadersImpl();

        CLIENT_REQUEST_HEADERS.addAccept(MediaType.TEXT_PLAIN);
        CLIENT_REQUEST_HEADERS.add(Http.Header.ACCEPT, MediaType.APPLICATION_JSON.toString());

        CLIENT_REQUEST_HEADERS.add(Http.Header.CONTENT_TYPE, MediaType.APPLICATION_XML.toString());
    }

    @Test
    public void testAcceptedTypes() {
        List<MediaType> types = new ArrayList<>();
        types.add(MediaType.TEXT_PLAIN);
        types.add(MediaType.APPLICATION_JSON);

        assertEquals(types, CLIENT_REQUEST_HEADERS.acceptedTypes());
    }

    @Test
    public void testContentType() {
        assertEquals(MediaType.APPLICATION_XML, CLIENT_REQUEST_HEADERS.mediaType().get());

        ClientRequestHeadersImpl empty = new ClientRequestHeadersImpl();
        assertEquals(MediaType.WILDCARD, empty.mediaType().get());

    }


}
