/*
 * Copyright (c) 2017, 2019 Oracle and/or its affiliates. All rights reserved.
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

package io.helidon.webserver;

import java.net.URI;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import io.helidon.common.http.DataChunk;
import io.helidon.common.http.MessageBody.Filter;
import io.helidon.common.reactive.Flow;
import io.helidon.common.reactive.ReactiveStreamsAdapter;
import io.helidon.webserver.utils.TestUtils;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.beans.HasPropertyWithValue.hasProperty;
import static org.hamcrest.core.AllOf.allOf;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import static io.helidon.common.reactive.ReactiveStreamsAdapter.publisherFromFlow;
import static io.helidon.common.reactive.ReactiveStreamsAdapter.publisherToFlow;

/**
 * The RequestContentTest.
 */
public class RequestContentTest {

    private static Request requestTestStub(Publisher<DataChunk> flux) {
        BareRequest bareRequestMock = Mockito.mock(BareRequest.class);
        Mockito.doReturn(URI.create("http://0.0.0.0:1234")).when(bareRequestMock).uri();
        Mockito.doReturn(publisherToFlow(flux)).when(bareRequestMock).bodyPublisher();
        return new RequestTestStub(bareRequestMock, Mockito.mock(WebServer.class));
    }

    @Test
    public void directSubscriptionTest() throws Exception {

        StringBuilder sb = new StringBuilder();
        Flux<DataChunk> flux = Flux.just("first", "second", "third").map(s -> DataChunk.create(s.getBytes()));

        Request request = requestTestStub(flux);

        ReactiveStreamsAdapter.publisherFromFlow(request.content())
                      .subscribe(chunk -> sb.append(TestUtils.requestChunkAsString(chunk))
                                            .append("-"));

        assertThat(sb.toString(), is("first-second-third-"));
    }

    @Test
    public void upperCaseFilterTest() throws Exception {

        StringBuilder sb = new StringBuilder();
        Flux<DataChunk> flux = Flux.just("first", "second", "third").map(s -> DataChunk.create(s.getBytes()));

        Request request = requestTestStub(flux);

        request.content().registerFilter((Flow.Publisher<DataChunk> publisher) -> {
            sb.append("apply_filter-");
            Flux<DataChunk> byteBufferFlux = publisherFromFlow(publisher);
            Flux<DataChunk> stringFlux = byteBufferFlux.map(TestUtils::requestChunkAsString)
                    .map(String::toUpperCase)
                    .map(s -> DataChunk.create(s.getBytes()));
            return ReactiveStreamsAdapter.publisherToFlow(stringFlux);
        });

        assertThat("Apply filter is expected to be called after a subscription!", sb.toString(), is(""));

        ReactiveStreamsAdapter.publisherFromFlow(request.content())
                      .subscribe(chunk -> sb.append(TestUtils.requestChunkAsString(chunk))
                                            .append("-"));

        assertThat(sb.toString(), is("apply_filter-FIRST-SECOND-THIRD-"));
    }

//    @Test
//    public void multiThreadingFilterAndReaderTest() throws Exception {
//
//        CountDownLatch subscribedLatch = new CountDownLatch(1);
//        SubmissionPublisher<DataChunk> publisher = new SubmissionPublisher<>(Runnable::run, 10);
//        ForkJoinPool.commonPool()
//                    .submit(() -> {
//                        try {
//                            if (!subscribedLatch.await(10, TimeUnit.SECONDS)) {
//                                fail("Subscriber didn't subscribe in timely manner!");
//                            }
//                        } catch (InterruptedException e) {
//                            Thread.currentThread().interrupt();
//                            throw new IllegalStateException("Interrupted!", e);
//                        }
//
//                        publisher.submit(DataChunk.create("first".getBytes()));
//                        publisher.submit(DataChunk.create("second".getBytes()));
//                        publisher.submit(DataChunk.create("third".getBytes()));
//
//                        publisher.close();
//                    });
//
//        Request request = requestTestStub(ReactiveStreamsAdapter.publisherFromFlow(publisher));
//
//        request.content()
//                .registerFilter(originalPublisher -> subscriberDelegate -> originalPublisher
//                        .subscribe(new Flow.Subscriber<DataChunk>() {
//                   @Override
//                   public void onSubscribe(Flow.Subscription subscription) {
//                       subscriberDelegate.onSubscribe(subscription);
//                       subscribedLatch.countDown();
//                   }
//
//                   @Override
//                   public void onNext(DataChunk item) {
//                       // mapping the on next call only
//                       subscriberDelegate.onNext(
//                               DataChunk.create(
//                                       TestUtils.requestChunkAsString(item).toUpperCase().getBytes()));
//                   }
//
//                   @Override
//                   public void onError(Throwable throwable) {
//                       subscriberDelegate.onError(throwable);
//                   }
//
//                   @Override
//                   public void onComplete() {
//                       subscriberDelegate.onComplete();
//                   }
//               }));
//        request.content()
//               .registerReader(Iterable.class, (publisher1, clazz) -> {
//                   fail("Iterable reader should have not been used!");
//                   throw new IllegalStateException("unreachable code");
//               });
//
//        request.content()
//               .registerReader(ArrayList.class, (publisher1, clazz) -> {
//                   fail("ArrayList reader should have not been used!");
//                   throw new IllegalStateException("unreachable code");
//               });
//
//        request.content()
//               .registerReader(List.class, (publisher1, clazz) -> {
//                   CompletableFuture<List> future = new CompletableFuture<>();
//                   List<String> list = new CopyOnWriteArrayList<>();
//
//                   publisher1.subscribe(new Flow.Subscriber<DataChunk>() {
//                       @Override
//                       public void onSubscribe(Flow.Subscription subscription) {
//                           subscription.request(Long.MAX_VALUE);
//                           subscribedLatch.countDown();
//                       }
//
//                       @Override
//                       public void onNext(DataChunk item) {
//                           list.add(TestUtils.requestChunkAsString(item));
//                       }
//
//                       @Override
//                       public void onError(Throwable throwable) {
//                           fail("Received an exception: " + throwable.getMessage());
//                       }
//
//                       @Override
//                       public void onComplete() {
//                           future.complete(list);
//                       }
//                   });
//                   return future;
//               });
//
//        List result = request.content().as(List.class).toCompletableFuture().get(10, TimeUnit.SECONDS);
//        assertThat((List<String>) result, hasItems(
//                is("FIRST"),
//                is("SECOND"),
//                is("THIRD")));
//    }

//    @Test
//    public void failingFilter() throws Exception {
//        Request request = requestTestStub(Mono.never());
//
//        request.content()
//               .registerFilter(publisher -> {
//                   throw new IllegalStateException("failed-publisher-transformation");
//               });
//        request.content()
//               .registerReader(Duration.class, (publisher, clazz) -> {
//                   fail("Should not be called");
//                   throw new IllegalStateException("unreachable code");
//               });
//
//        CompletableFuture<?> future = request.content().as(Duration.class).toCompletableFuture();
//        try {
//            future.get(10, TimeUnit.SECONDS);
//            fail("Should have thrown an exception");
//        } catch (ExecutionException e) {
//            assertThat(e.getCause(), allOf(instanceOf(IllegalArgumentException.class),
//                                           hasProperty("message", containsString("Transformation failed!"))));
//            assertThat(e.getCause().getCause(), hasProperty("message", containsString("failed-publisher-transformation")));
//        }
//    }

//    @Test
//    public void failingReader() throws Exception {
//        Request request = requestTestStub(Mono.never());
//
//        request.content()
//               .registerReader(Duration.class, (publisher, clazz) -> {
//                   throw new IllegalStateException("failed-read");
//               });
//
//        CompletableFuture<?> future = request.content().as(Duration.class).toCompletableFuture();
//        try {
//            future.get(10, TimeUnit.SECONDS);
//            fail("Should have thrown an exception");
//        } catch (ExecutionException e) {
//            assertThat(e.getCause(), allOf(instanceOf(IllegalArgumentException.class),
//                                           hasProperty("message", containsString("Transformation failed!"))));
//            assertThat(e.getCause().getCause(), hasProperty("message", containsString("failed-read")));
//        }
//    }

//    @Test
//    public void missingReaderTest() throws Exception {
//        Request request = requestTestStub(Mono.just(DataChunk.create("hello".getBytes())));
//
//        request.content()
//                .registerReader(LocalDate.class, (publisher, clazz) -> {
//                    throw new IllegalStateException("Should not be called");
//                });
//
//        CompletableFuture<?> future = request.content().as(Duration.class).toCompletableFuture();
//        try {
//            future.get(10, TimeUnit.SECONDS);
//            fail("Should have thrown an exception");
//        } catch (ExecutionException e) {
//            assertThat(e.getCause(), instanceOf(IllegalArgumentException.class));
//        }
//    }

    @Test
    public void nullFilter() throws Exception {
        Request request = requestTestStub(Mono.never());

        assertThrows(NullPointerException.class, () -> {
            request.content().registerFilter((Filter)null);
        });
    }

    @Test
    public void failingSubscribe() throws Exception {
        Request request = requestTestStub(Flux.just(DataChunk.create("data".getBytes())));

        request.content()
                .registerFilter((Flow.Publisher<DataChunk> publisher) -> {
                    throw new IllegalStateException("failed-publisher-transformation");
        });

        AtomicReference<Throwable> receivedThrowable = new AtomicReference<>();

        ReactiveStreamsAdapter.publisherFromFlow(request.content())
                      .subscribe(byteBuffer -> {
                                     fail("Should not have been called!");
                                 },
                                 receivedThrowable::set);

        Throwable throwable = receivedThrowable.get();
        assertThat(throwable, allOf(instanceOf(IllegalArgumentException.class),
                                    hasProperty("message",
                                                containsString("Unexpected exception occurred during publishers chaining"))));
        assertThat(throwable.getCause(), hasProperty("message",
                                                     containsString("failed-publisher-transformation")));
    }

//    @Test
//    public void readerTest() throws Exception {
//
//        Flux<DataChunk> flux = Flux.just("2010-01-02").map(s -> DataChunk.create(s.getBytes()));
//
//        Request request = requestTestStub(flux);
//
//        request.content()
//               .registerReader(LocalDate.class,
//                               (publisher, clazz) -> ContentReaders.stringReader(Request.requestContentCharset(request))
//                               .apply(publisher)
//                               .thenApply(LocalDate::parse));
//
//        CompletionStage<String> complete =
//                request.content()
//                       .as(LocalDate.class)
//                       .thenApply(o -> o.getDayOfMonth()
//                               + "/"
//                               + o.getMonthValue()
//                               + "/"
//                               + o.getYear());
//
//        String result = complete.toCompletableFuture().get(10, TimeUnit.SECONDS);
//        assertThat(result, is("2/1/2010"));
//    }

    @Test
    public void implicitByteArrayContentReader() throws Exception {
        Flux<DataChunk> flux = Flux.just("test-string").map(s -> DataChunk.create(s.getBytes()));
        Request request = requestTestStub(flux);

        CompletionStage<String> complete = request.content().as(byte[].class).thenApply(String::new);

        assertThat(complete.toCompletableFuture().get(10, TimeUnit.SECONDS), is("test-string"));
    }

    @Test
    public void implicitStringContentReader() throws Exception {
        Flux<DataChunk> flux = Flux.just("test-string").map(s -> DataChunk.create(s.getBytes()));
        Request request = requestTestStub(flux);

        CompletionStage<? extends String> complete = request.content().as(String.class);

        assertThat(complete.toCompletableFuture().get(10, TimeUnit.SECONDS), is("test-string"));
    }

//    @Test
//    public void overridingStringContentReader() throws Exception {
//        Flux<DataChunk> flux = Flux.just("test-string").map(s -> DataChunk.create(s.getBytes()));
//        Request request = requestTestStub(flux);
//
//        request.content()
//               .registerReader(String.class, (publisher, clazz) -> {
//                   fail("Should not be called");
//                   throw new IllegalStateException("unreachable code");
//               });
//        request.content()
//               .registerReader(String.class, (publisher, clazz) -> {
//                   Flux<DataChunk> byteBufferFlux = ReactiveStreamsAdapter.publisherFromFlow(publisher);
//                   return byteBufferFlux.map(TestUtils::requestChunkAsString)
//                                        .map(String::toUpperCase)
//                                        .collect(Collectors.joining())
//                                        .toFuture();
//               });
//
//        CompletionStage<? extends String> complete = request.content().as(String.class);
//
//        assertThat(complete.toCompletableFuture().get(10, TimeUnit.SECONDS), is("TEST-STRING"));
//    }
}
