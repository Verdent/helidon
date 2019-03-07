package io.helidon.microprofile.restClient;

import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import org.glassfish.jersey.internal.inject.InjectionManager;
import org.glassfish.jersey.internal.util.collection.Ref;

/**
 * Created by David Kral.
 */
public class ClientHeaderFilter implements ClientRequestFilter {

    @Context
    private InjectionManager injectionManager;

    @Override
    public void filter(ClientRequestContext requestContext) {
        //Adds support for HttpHeaders injection
        injectionManager.<Ref<HttpHeaders>>getInstance((new GenericType<Ref<HttpHeaders>>() { }).getType())
                .set(new HelidonHttpHeaders(requestContext.getStringHeaders()));

    }

    private static class HelidonHttpHeaders implements HttpHeaders {

        private MultivaluedMap<String, String> headers;

        public HelidonHttpHeaders(MultivaluedMap<String, String> headers) {
            this.headers = headers;
        }

        @Override
        public List<String> getRequestHeader(String name) {
            return headers.get(name);
        }

        @Override
        public String getHeaderString(String name) {
            return headers.getFirst(name);
        }

        @Override
        public MultivaluedMap<String, String> getRequestHeaders() {
            return headers;
        }

        @Override
        public List<MediaType> getAcceptableMediaTypes() {
            return null;
        }

        @Override
        public List<Locale> getAcceptableLanguages() {
            return null;
        }

        @Override
        public MediaType getMediaType() {
            return null;
        }

        @Override
        public Locale getLanguage() {
            return null;
        }

        @Override
        public Map<String, Cookie> getCookies() {
            return null;
        }

        @Override
        public Date getDate() {
            return null;
        }

        @Override
        public int getLength() {
            return 0;
        }
    }
}
