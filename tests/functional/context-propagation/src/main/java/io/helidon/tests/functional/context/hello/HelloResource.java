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

import java.util.logging.Logger;

import io.helidon.webserver.http.ServerRequest;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.container.AsyncResponse;
import jakarta.ws.rs.container.Suspended;
import org.eclipse.microprofile.faulttolerance.CircuitBreaker;
import org.eclipse.microprofile.faulttolerance.Retry;

/**
 * HelloResource class.
 */
@Path("/")
public class HelloResource {

    private HelloBean helloBean;

    @Inject
    private ServerRequestSupplier supplier;

    /**
     * Constructor.
     *
     * @param helloBean Injected bean.
     */
    @Inject
    public HelloResource(HelloBean helloBean) {
        this.helloBean = helloBean;
    }

    /**
     * Method getHello().
     *
     * @return Hello string.
     */
    @GET
    @Path("/hello")
    @Retry
    @CircuitBreaker
    public String getHello() {
        return helloBean.getHello();
    }

    /**
     * Method getHelloTimeout().
     *
     * @return Hello string.
     */
    @GET
    @Path("/helloTimeout")
    @Retry
    @CircuitBreaker
    public String getHelloTimeout() {
        return helloBean.getHelloTimeout();
    }

    /**
     * Method getHelloAsync().
     *
     * @return Hello string.
     * @throws Exception If an error occurs.
     */
    @GET
    @Path("/helloAsync")
    @Retry
    @CircuitBreaker
    public String getHelloAsync() throws Exception {
        return helloBean.getHelloAsync().toCompletableFuture().get();
    }

    @GET
    @Path("/remoteAddress")
    @Retry
    @CircuitBreaker
    public String getRemoteAddress() {
        ServerRequest serverRequest = supplier.get();
        return serverRequest.remotePeer().host();
    }


    private static final Logger LOGGER = Logger.getLogger(HelloResource.class.getName());

    /**
     * Long-running asynchronous post.
     *
     * @param asyncResponse async response.
     * @param id            post request id (received as request payload).
     */
    @POST
    @Path("async")
    public void asyncPost(@Suspended final AsyncResponse asyncResponse, final String id) {
        System.out.println("PRDEEEEL - " + id);
        LOGGER.info("Long running post operation called with id " + id + " on thread " + Thread.currentThread().getName());
        new Thread(new Runnable() {

            @Override
            public void run() {
                final String result = veryExpensiveOperation();
                asyncResponse.resume(result);
            }

            private String veryExpensiveOperation() {
                // ... very expensive operation that typically finishes within 1 seconds, simulated using sleep()
                try {
                    Thread.sleep(1000);
                    return "DONE-" + id;
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return "INTERRUPTED-" + id;
                } finally {
                    LOGGER.info("Long running post operation finished on thread " + Thread.currentThread().getName());
                }
            }
        }, "async-post-runner-" + id).start();
    }
}
