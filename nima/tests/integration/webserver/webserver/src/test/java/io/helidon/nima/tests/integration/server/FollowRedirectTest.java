package io.helidon.nima.tests.integration.server;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import io.helidon.common.http.Http;
import io.helidon.nima.testing.junit5.webserver.ServerTest;
import io.helidon.nima.testing.junit5.webserver.SetUpRoute;
import io.helidon.nima.webclient.http1.Http1Client;
import io.helidon.nima.webclient.http1.Http1ClientResponse;
import io.helidon.nima.webserver.http.HttpRouting;

import org.junit.jupiter.api.Test;

import static io.helidon.common.http.Http.Status.INTERNAL_SERVER_ERROR_500;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ServerTest
class FollowRedirectTest {
    private final Http1Client webClient;

    FollowRedirectTest(Http1Client client) {
        this.webClient = client;
    }

    @SetUpRoute
    static void router(HttpRouting.Builder router) {
        router.route(Http.Method.PUT, "/infiniteRedirect", (req, res) -> {
            res.status(Http.Status.TEMPORARY_REDIRECT_307)
                    .header(Http.Header.LOCATION, "/infiniteRedirect2")
                    .send();
        }).route(Http.Method.PUT, "/infiniteRedirect2", (req, res) -> {
            res.status(Http.Status.TEMPORARY_REDIRECT_307)
                    .header(Http.Header.LOCATION, "/infiniteRedirect")
                    .send();
        }).route(Http.Method.PUT, "/redirect", (req, res) -> {
            res.status(Http.Status.TEMPORARY_REDIRECT_307)
                    .header(Http.Header.LOCATION, "/plain")
                    .send();
        }).route(Http.Method.PUT, "/redirectNoEntity", (req, res) -> {
            res.status(Http.Status.FOUND_302)
                    .header(Http.Header.LOCATION, "/plain")
                    .send();
        }).route(Http.Method.PUT, "/plain", (req, res) -> {
            try (InputStream in = req.content().inputStream()) {
                StringBuilder sb = new StringBuilder();
                byte[] buffer = new byte[128];
                int read;
                while ((read = in.read(buffer)) > 0) {
                    sb.append(new String(buffer, 0, read)).append("\n");
                }
                res.send("Test data:\n" + sb);
            } catch (Exception e) {
                res.status(INTERNAL_SERVER_ERROR_500)
                        .send(e.getMessage());
            }
        }).route(Http.Method.GET, "/plain", (req, res) -> {
            res.send("GET plain endpoint reached");
        }).route(Http.Method.PUT, "/close", (req, res) -> {
            byte[] buffer = new byte[10];
            try (InputStream in = req.content().inputStream()) {
                in.read(buffer);
                throw new RuntimeException("BOOM!");
            } catch (IOException e) {
                res.status(INTERNAL_SERVER_ERROR_500)
                        .send(e.getMessage());
            }
        });
    }

    @Test
    void testOutputStreamFollowRedirect() {
        String expected = """
                Test data:
                0123456789
                0123456789
                0123456789
                """;
        try (Http1ClientResponse response = webClient.put()
                .path("/redirect")
                .outputStream(it -> {
                    it.write("0123456789".getBytes(StandardCharsets.UTF_8));
                    it.write("0123456789".getBytes(StandardCharsets.UTF_8));
                    it.write("0123456789".getBytes(StandardCharsets.UTF_8));
                    it.close();
                })) {
            assertThat(response.entity().as(String.class), is(expected));
        }
    }

    @Test
    void testOutputStreamEntityNotKept() {
        String expected = "GET plain endpoint reached";
        try (Http1ClientResponse response = webClient.put()
                .path("/redirectNoEntity")
                .outputStream(it -> {
//                    it.write("0123456789".getBytes(StandardCharsets.UTF_8));
//                    it.write("0123456789".getBytes(StandardCharsets.UTF_8));
//                    it.write("0123456789".getBytes(StandardCharsets.UTF_8));
                    it.close();
                })) {
            assertThat(response.entity().as(String.class), is(expected));
        }
    }

    @Test
    void testOutputStreamEntityNotKeptIntercepted() {
        String expected = "GET plain endpoint reached";
        try (Http1ClientResponse response = webClient.put()
                .path("/redirectNoEntity")
                .outputStream(it -> {
                    try {
                        it.write("0123456789".getBytes(StandardCharsets.UTF_8));
                        it.write("0123456789".getBytes(StandardCharsets.UTF_8));
                        it.write("0123456789".getBytes(StandardCharsets.UTF_8));
                        it.close();
                    } catch (Exception ignore) {
                    }
                })) {
            assertThat(response.entity().as(String.class), is(expected));
        }
    }

    @Test
    void testMaxNumberOfRedirections() {
        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> webClient.put()
                .path("/infiniteRedirect")
                .outputStream(it -> {
                    it.write("0123456789".getBytes(StandardCharsets.UTF_8));
                    it.write("0123456789".getBytes(StandardCharsets.UTF_8));
                    it.close();
                }));
        assertThat(exception.getMessage(), is("Maximum number of request redirections (10) reached."));
    }

}
