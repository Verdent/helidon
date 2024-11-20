/*
 * Copyright (c) 2019, 2023 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.tests.functional.context.hello;

import java.util.concurrent.Future;

import io.helidon.microprofile.testing.junit5.HelidonTest;

import jakarta.inject.Inject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit test for {@link HelloResource}.
 */
@HelidonTest
class HelloTest {
    private final WebTarget baseTarget;

    @Inject
    HelloTest(WebTarget baseTarget) {
        this.baseTarget = baseTarget;
    }

    @Test
    void testHello() {
        WebTarget target = baseTarget.path("/hello");
        assertOk(target.request().get(), "Hello World");
    }

    @Test
    void testHelloTimeout() {
        WebTarget target = baseTarget.path("/helloTimeout");
        assertOk(target.request().get(), "Hello World");
    }

    @Test
    void testHelloAsync() {
        WebTarget target = baseTarget.path("/helloAsync");
        assertOk(target.request().get(), "Hello World");
    }

    @Test
    void testRemoteAddress() {
        WebTarget target = baseTarget.path("/remoteAddress");
        assertThat(target.request().get().getStatus(), is(200));
    }

    private void assertOk(Response response, String expectedMessage) {
        assertThat(response.getStatus(), is(200));
        assertThat(response.readEntity(String.class), is(expectedMessage));
    }

    @Test
    public void testAsyncPost() throws Exception {
        final Future<Response> warmUp1 = baseTarget.path("async").request().async().post(Entity.text("100"));
        final Future<Response> warmUp2 = baseTarget.path("async").request().async().post(Entity.text("200"));
        final Future<Response> warmUp3 = baseTarget.path("async").request().async().post(Entity.text("300"));
        //        final Future<Response> warmUp4 = target(PATH).request().async().post(Entity.text("1"));
        //        final Future<Response> warmUp5 = target(PATH).request().async().post(Entity.text("300"));
        //        final Future<Response> warmUp6 = target(PATH).request().async().post(Entity.text("300"));
        //        final Future<Response> warmUp7 = target(PATH).request().async().post(Entity.text("300"));

        assertEquals("DONE-100", warmUp1.get().readEntity(String.class));
        assertEquals("DONE-200", warmUp2.get().readEntity(String.class));
        assertEquals("DONE-300", warmUp3.get().readEntity(String.class));
        //        assertEquals("DONE-1", warmUp4.get().readEntity(String.class));
        //        assertEquals("DONE-300", warmUp5.get().readEntity(String.class));
        //        assertEquals("DONE-300", warmUp6.get().readEntity(String.class));
        //        assertEquals("DONE-300", warmUp7.get().readEntity(String.class));
        final Future<Response> rf1 = baseTarget.path("async").request().async().post(Entity.text("1"));
        final Future<Response> rf2 = baseTarget.path("async").request().async().post(Entity.text("2"));
        final Future<Response> rf3 = baseTarget.path("async").request().async().post(Entity.text("3"));


        final String r1 = rf1.get().readEntity(String.class);
        final String r2 = rf2.get().readEntity(String.class);
        final String r3 = rf3.get().readEntity(String.class);

        assertEquals("DONE-1", r1);
        assertEquals("DONE-2", r2);
        assertEquals("DONE-3", r3);
        //
        //        final long tic = System.currentTimeMillis();
        //
        //        // Submit requests asynchronously.
        //        final Future<Response> rf1 = target(PATH).request().async().post(Entity.text("1"));
        //        final Future<Response> rf2 = target(PATH).request().async().post(Entity.text("2"));
        //        final Future<Response> rf3 = target(PATH).request().async().post(Entity.text("3"));
        //
        //        // get() waits for the response
        //        final String r1 = rf1.get().readEntity(String.class);
        //        final String r2 = rf2.get().readEntity(String.class);
        //        final String r3 = rf3.get().readEntity(String.class);
        //
        //        final long toc = System.currentTimeMillis();
        //
        //        assertEquals("DONE-1", r1);
        //        assertEquals("DONE-2", r2);
        //        assertEquals("DONE-3", r3);
        //
        //        assertThat("Async processing took too long.", toc - tic, Matchers.lessThan(3 * AsyncResource.OPERATION_DURATION));
    }



}