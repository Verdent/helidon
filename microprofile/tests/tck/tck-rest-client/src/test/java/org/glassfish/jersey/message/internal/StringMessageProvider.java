package org.glassfish.jersey.message.internal;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import javax.inject.Singleton;

/*
 * This class was copied from Jersey Common 2.26 due to TCK workaround reasons.
 */
/**
 *
 * @author Paul Sandoz
 */
@Produces
@Consumes
@Singleton
final class StringMessageProvider extends AbstractMessageReaderWriterProvider<String> {

    @Override
    public boolean isReadable(Class<?> type, Type genericType, Annotation annotations[], MediaType mediaType) {
        return type == String.class;
    }

    @Override
    public String readFrom(
            Class<String> type,
            Type genericType,
            Annotation annotations[],
            MediaType mediaType,
            MultivaluedMap<String, String> httpHeaders,
            InputStream entityStream) throws IOException {
        return readFromAsString(entityStream, mediaType);
    }

    @Override
    public boolean isWriteable(Class<?> type, Type genericType, Annotation annotations[], MediaType mediaType) {
        return type == String.class;
    }

    @Override
    public long getSize(String s, Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType) {
        return s.length();
    }

    @Override
    public void writeTo(
            String t,
            Class<?> type,
            Type genericType,
            Annotation annotations[],
            MediaType mediaType,
            MultivaluedMap<String, Object> httpHeaders,
            OutputStream entityStream) throws IOException {
        writeToAsString(t, entityStream, mediaType);
    }
}
