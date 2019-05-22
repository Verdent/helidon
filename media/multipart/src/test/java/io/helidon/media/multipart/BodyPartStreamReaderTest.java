/*
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
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
package io.helidon.media.multipart;

import io.helidon.common.http.DataChunk;
import io.helidon.common.reactive.Flow;
import io.helidon.common.reactive.Flow.Publisher;
import io.helidon.common.reactive.Flow.Subscriber;
import io.helidon.common.reactive.Flow.Subscription;
import io.helidon.webserver.HashRequestHeaders;
import io.helidon.webserver.RequestHeaders;
import io.helidon.webserver.Request;
import io.helidon.webserver.Response;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static io.helidon.common.CollectionsHelper.listOf;
import static io.helidon.common.CollectionsHelper.mapOf;
import static io.helidon.media.multipart.BodyPartTest.READERS;
import static io.helidon.media.multipart.BodyPartTest.WRITERS;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Tests {@link BodyPartStreamReader}.
 */
public class BodyPartStreamReaderTest {

    @Test
    public void testOnePartInOneChunk() {
        String boundary = "boundary";
        final byte[] chunk1 = ("--" + boundary + "\n"
                + "Content-Id: part1\n"
                + "\n"
                + "body 1\n"
                + "--" + boundary + "--").getBytes();

        final CountDownLatch latch = new CountDownLatch(2);
        Consumer<BodyPart> consumer = (part) -> {
            latch.countDown();
            assertThat(part.headers().values("Content-Id"),
                    hasItems("part1"));
            PartContentSubscriber subscriber = new PartContentSubscriber();
            part.content().subscribe(subscriber);
            subscriber.content().thenAccept(body -> {
                latch.countDown();
                assertThat(body, is(equalTo("body 1")));
            });
        };
        TestSubscriber testSubscriber = new TestSubscriber(
                SUBSCRIBER_TYPE.INFINITE, consumer);
        partsPublisher(boundary, chunk1).subscribe(testSubscriber);
        waitOnLatch(latch);
        assertThat(testSubscriber.error, is(nullValue()));
        assertThat(testSubscriber.complete, is(equalTo(true)));
    }

    @Test
    public void testTwoPartsInOneChunk() {
        String boundary = "boundary";
        final byte[] chunk1 = ("--" + boundary + "\n"
                + "Content-Id: part1\n"
                + "\n"
                + "body 1\n"
                + "--" + boundary + "\n"
                + "Content-Id: part2\n"
                + "\n"
                + "body 2\n"
                + "--" + boundary + "--").getBytes();

        final CountDownLatch latch = new CountDownLatch(4);
        Consumer<BodyPart> consumer = (part) -> {
            latch.countDown();
            if (latch.getCount() == 3) {
                assertThat(part.headers().values("Content-Id"),
                        hasItems("part1"));
                PartContentSubscriber subscriber = new PartContentSubscriber();
                part.content().subscribe(subscriber);
                subscriber.content().thenAccept(body -> {
                    latch.countDown();
                    assertThat(body, is(equalTo("body 1")));
                });
            } else {
                assertThat(part.headers().values("Content-Id"),
                        hasItems("part2"));
                PartContentSubscriber subscriber = new PartContentSubscriber();
                part.content().subscribe(subscriber);
                subscriber.content().thenAccept(body -> {
                    latch.countDown();
                    assertThat(body, is(equalTo("body 2")));
                });
            }
        };
        TestSubscriber testSubscriber = new TestSubscriber(
                SUBSCRIBER_TYPE.INFINITE, consumer);
        partsPublisher(boundary, chunk1).subscribe(testSubscriber);
        waitOnLatch(latch);
        assertThat(testSubscriber.error, is(nullValue()));
        assertThat(testSubscriber.complete, is(equalTo(true)));
    }

    @Test
    public void testContentAcrossChunks() {
        String boundary = "boundary";
        final byte[] chunk1 = ("--" + boundary + "\n"
                + "Content-Id: part1\n"
                + "\n"
                + "this-is-the-1st-slice-of-the-body\n").getBytes();
        final byte[] chunk2 = ("this-is-the-2nd-slice-of-the-body\n"
                + "--" + boundary + "--").getBytes();

        final CountDownLatch latch = new CountDownLatch(2);
        Consumer<BodyPart> consumer = (part) -> {
            latch.countDown();
            assertThat(part.headers().values("Content-Id"), hasItems("part1"));
            PartContentSubscriber subscriber = new PartContentSubscriber();
            part.content().subscribe(subscriber);
            subscriber.content().thenAccept(body -> {
                latch.countDown();
                assertThat(body, is(equalTo(
                        "this-is-the-1st-slice-of-the-body\n"
                        + "this-is-the-2nd-slice-of-the-body")));
            });
        };
        TestSubscriber testSubscriber = new TestSubscriber(
                SUBSCRIBER_TYPE.INFINITE, consumer);
        partsPublisher(boundary, chunk1, chunk2).subscribe(testSubscriber);
        waitOnLatch(latch);
        assertThat(testSubscriber.error, is(nullValue()));
        assertThat(testSubscriber.complete, is(equalTo(true)));
    }

    @Test
    public void testMultipleChunksBeforeContent() {
        String boundary = "boundary";
        final byte[] chunk1 = ("--" + boundary + "\n"
                + "Content-Id: part1\n").getBytes();
        final byte[] chunk2 = "Content-Type: text/plain\n".getBytes();
        final byte[] chunk3 = "Set-Cookie: bob=alice\n".getBytes();
        final byte[] chunk4 = "Set-Cookie: foo=bar\n".getBytes();
        final byte[] chunk5 = ("\n"
                + "body 1\n"
                + "--" + boundary + "--").getBytes();

        final CountDownLatch latch = new CountDownLatch(2);
        Consumer<BodyPart> consumer = (part) -> {
            latch.countDown();
            assertThat(part.headers().values("Content-Id"), hasItems("part1"));
            assertThat(part.headers().values("Content-Type"),
                    hasItems("text/plain"));
            assertThat(part.headers().values("Set-Cookie"),
                    hasItems("bob=alice", "foo=bar"));
            PartContentSubscriber subscriber = new PartContentSubscriber();
            part.content().subscribe(subscriber);
            subscriber.content().thenAccept(body -> {
                latch.countDown();
                assertThat(body, is(equalTo("body 1")));
            });
        };
        TestSubscriber testSubscriber = new TestSubscriber(
                SUBSCRIBER_TYPE.INFINITE, consumer);
        partsPublisher(boundary, chunk1, chunk2, chunk3, chunk4, chunk5)
                .subscribe(testSubscriber);
        waitOnLatch(latch);
        assertThat(testSubscriber.error, is(nullValue()));
        assertThat(testSubscriber.complete, is(equalTo(true)));
    }

    @Test
    public void testMulitiplePartsWithOneByOneSubscriber() {
        String boundary = "boundary";
        final byte[] chunk1 = ("--" + boundary + "\n"
                + "Content-Id: part1\n"
                + "\n"
                + "body 1\n"
                + "--" + boundary + "\n"
                + "Content-Id: part2\n"
                + "\n"
                + "body 2\n"
                + "--" + boundary + "--").getBytes();

        final CountDownLatch latch = new CountDownLatch(4);
        Consumer<BodyPart> consumer = (part) -> {
            latch.countDown();
            if (latch.getCount()== 3) {
                assertThat(part.headers().values("Content-Id"),
                        hasItems("part1"));
                PartContentSubscriber subscriber = new PartContentSubscriber();
                part.content().subscribe(subscriber);
                subscriber.content().thenAccept(body -> {
                    latch.countDown();
                    assertThat(body, is(equalTo("body 1")));
                });
            } else {
                assertThat(part.headers().values("Content-Id"),
                        hasItems("part2"));
                PartContentSubscriber subscriber = new PartContentSubscriber();
                part.content().subscribe(subscriber);
                subscriber.content().thenAccept(body -> {
                    latch.countDown();
                    assertThat(body, is(equalTo("body 2")));
                });
            }
        };
        TestSubscriber testSubscriber = new TestSubscriber(
                SUBSCRIBER_TYPE.ONE_BY_ONE, consumer);
        partsPublisher(boundary, chunk1)
                .subscribe(testSubscriber);
        waitOnLatch(latch);
        assertThat(testSubscriber.error, is(nullValue()));
        assertThat(testSubscriber.complete, is(equalTo(true)));
    }

    @Test
    public void testSubscriberCancelAfterOnePart() {
        String boundary = "boundary";
        final byte[] chunk1 = ("--" + boundary + "\n"
                + "Content-Id: part1\n"
                + "\n"
                + "body 1\n"
                + "--" + boundary + "\n"
                + "Content-Id: part2\n"
                + "\n"
                + "body 2\n"
                + "--" + boundary + "--").getBytes();

        final CountDownLatch latch = new CountDownLatch(2);
        Consumer<BodyPart> consumer = (part) -> {
            latch.countDown();
            if (latch.getCount()== 1) {
                assertThat(part.headers().values("Content-Id"),
                        hasItems("part1"));
                PartContentSubscriber subscriber1 =
                        new PartContentSubscriber();
                part.content().subscribe(subscriber1);
                subscriber1.content().thenAccept(body -> {
                    latch.countDown();
                    assertThat(body, is(equalTo("body 1")));
                });
            }
        };

        TestSubscriber testSubscriber = new TestSubscriber(
                SUBSCRIBER_TYPE.CANCEL_AFTER_ONE, consumer);
        partsPublisher(boundary, chunk1)
                .subscribe(testSubscriber);
        waitOnLatch(latch);
        assertThat(testSubscriber.error, is(nullValue()));
        assertThat(testSubscriber.complete, is(equalTo(false)));
    }

    @Test
    public void testNoClosingBoundary(){
        String boundary = "boundary";
        final byte[] chunk1 = ("--" + boundary + "\n"
                + "Content-Type: text/xml; charset=UTF-8\n"
                + "Content-Id: part1\n"
                + "\n"
                + "<foo>bar</foo>\n").getBytes();

        TestSubscriber testSubscriber = new TestSubscriber(
                SUBSCRIBER_TYPE.CANCEL_AFTER_ONE, null);
        partsPublisher(boundary, chunk1)
                .subscribe(testSubscriber);
        assertThat(testSubscriber.complete, is(equalTo(false)));
        assertThat(testSubscriber.error.getClass(),
                is(equalTo(MIMEParsingException.class)));
        assertThat(testSubscriber.error.getMessage(),
                is(equalTo("No closing MIME boundary")));
    }

    @Test
    public void testCanceledPartSubscription() {
        String boundary = "boundary";
        final byte[] chunk1 = ("--" + boundary + "\n"
                + "Content-Id: part1\n"
                + "\n"
                + "body 1.aaaa\n").getBytes();
        final byte[] chunk2 = "body 1.bbbb\n".getBytes();
        final byte[] chunk3 = ("body 1.cccc\n"
                + "--" + boundary + "\n"
                + "Content-Id: part2\n"
                + "\n"
                + "This is the 2nd").getBytes();
        final byte[] chunk4 = ("body.\n"
                + "--" + boundary + "--").getBytes();

        final CountDownLatch latch = new CountDownLatch(4);
        Consumer<BodyPart> consumer = (part) -> {
            latch.countDown();
            if (latch.getCount() == 3) {
                assertThat(part.headers().values("Content-Id"),
                        hasItems("part1"));
                part.content().subscribe(new Subscriber<DataChunk>() {
                    Subscription subscription;

                    @Override
                    public void onSubscribe(Subscription subscription) {
                        this.subscription = subscription;
                        subscription.request(Long.MAX_VALUE);
                    }

                    @Override
                    public void onNext(DataChunk item) {
                        latch.countDown();
                        subscription.cancel();
                    }

                    @Override
                    public void onError(Throwable throwable) {
                    }

                    @Override
                    public void onComplete() {
                    }
                });
            } else {
                assertThat(part.headers().values("Content-Id"),
                        hasItems("part2"));
                PartContentSubscriber subscriber = new PartContentSubscriber();
                part.content().subscribe(subscriber);
                subscriber.content().thenAccept(body -> {
                    latch.countDown();
                    assertThat(body,is(equalTo("This is the 2nd body.")));
                });
            }
        };
        TestSubscriber testSubscriber = new TestSubscriber(
                SUBSCRIBER_TYPE.ONE_BY_ONE, consumer);
        partsPublisher(boundary, chunk1, chunk2, chunk3, chunk4)
                .subscribe(testSubscriber);
        waitOnLatch(latch);
        assertThat(testSubscriber.error, is(nullValue()));
        assertThat(testSubscriber.complete, is(equalTo(true)));
    }

    @Test
    public void testPartContentSubscriberThrottling() {
        String boundary = "boundary";
        final byte[] chunk1 = ("--" + boundary + "\n"
                + "Content-Id: part1\n"
                + "\n"
                + "body 1.aaaa\n").getBytes();
        final byte[] chunk2 = "body 1.bbbb\n".getBytes();
        final byte[] chunk3 = ("body 1.cccc\n"
                + "--" + boundary + "\n"
                + "Content-Id: part2\n"
                + "\n"
                + "This is the 2nd").getBytes();
        final byte[] chunk4 = ("body.\n"
                + "--" + boundary + "--").getBytes();

        final CountDownLatch latch = new CountDownLatch(3);
        Consumer<BodyPart> consumer = (part) -> {
            latch.countDown();
            if (latch.getCount() == 2) {
                assertThat(part.headers().values("Content-Id"),
                        hasItems("part1"));
            }
            part.content().subscribe(new Subscriber<DataChunk>() {

                @Override
                public void onSubscribe(Subscription subscription) {
                    subscription.request(1);
                }

                @Override
                public void onNext(DataChunk item) {
                    latch.countDown();
                }

                @Override
                public void onError(Throwable throwable) {
                }

                @Override
                public void onComplete() {
                }
            });
        };
        TestSubscriber testSubscriber = new TestSubscriber(
                SUBSCRIBER_TYPE.ONE_BY_ONE, consumer);
        partsPublisher(boundary, chunk1, chunk2, chunk3, chunk4)
                .subscribe(testSubscriber);
        waitOnLatchNegative(latch, "the 2nd part should not be processed");
        assertThat(latch.getCount(), is(equalTo(1L)));
        assertThat(testSubscriber.error, is(nullValue()));
        assertThat(testSubscriber.complete, is(equalTo(false)));
    }

    /**
     * Types of test subscribers.
     */
    enum SUBSCRIBER_TYPE {
        INFINITE,
        ONE_BY_ONE,
        CANCEL_AFTER_ONE,
    }

    /**
     * A part test subscriber.
     */
    static class TestSubscriber implements Subscriber<BodyPart>{

        private final SUBSCRIBER_TYPE subscriberType;
        private final Consumer<BodyPart> consumer;
        private Subscription subcription;
        private Throwable error;
        private boolean complete;

        TestSubscriber(SUBSCRIBER_TYPE subscriberType,
                Consumer<BodyPart> consumer) {

            this.subscriberType = subscriberType;
            this.consumer = consumer;
        }

        @Override
        public void onSubscribe(Subscription subscription) {
            this.subcription = subscription;
            if (subscriberType == SUBSCRIBER_TYPE.INFINITE) {
                subscription.request(Long.MAX_VALUE);
            } else {
                subscription.request(1);
            }
        }

        @Override
        public void onNext(BodyPart item) {
            if (consumer == null){
                return;
            }
            consumer.accept(item);
            if (subscriberType == SUBSCRIBER_TYPE.ONE_BY_ONE) {
                subcription.request(1);
            } else if (subscriberType == SUBSCRIBER_TYPE.CANCEL_AFTER_ONE) {
                subcription.cancel();
            }
        }

        @Override
        public void onError(Throwable ex) {
            error = ex;
        }

        @Override
        public void onComplete() {
            complete = true;
        }
    }

    /**
     * Create the parts publisher for the specified boundary and request
     * chunks.
     * @param boundary multipart boundary string
     * @param chunks request chunks
     * @return publisher of body parts
     */
    static Publisher<BodyPart> partsPublisher(String boundary,
            byte[]... chunks) {

        // mock response
        Response responseMock = Mockito.mock(Response.class);
        Mockito.doReturn(WRITERS).when(responseMock).getWriters();

        // mock request
        Request requestMock = Mockito.mock(Request.class);
        Request.Content contentMock = Mockito.mock(Request.Content.class);
        Mockito.doReturn(READERS).when(contentMock).getReaders();
        Mockito.doReturn(contentMock).when(requestMock).content();

        // multipart headers
        RequestHeaders headers = new HashRequestHeaders(
                mapOf("Content-Type",
                        listOf("multipart/form-data ; boundary="
                                + boundary)));
        Mockito.doReturn(headers).when(requestMock).headers();

        return new BodyPartStreamReader(requestMock, responseMock)
                    .apply(new DataChunkPublisher(chunks));
    }

    /**
     * Wait on the given latch for {@code 5 seconds} and emit an assertion
     * failure if the latch countdown is not zero.
     *
     * @param latch the latch
     */
    static void waitOnLatch(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) {
                fail("timeout");
            }
        } catch (InterruptedException ex) {
            fail(ex);
        }
    }

    /**
     * Wait on the given latch for {@code 5 seconds} and emit an assertion
     * failure if the latch countdown is zero.
     *
     * @param latch the latch
     * @param failMsg message to the assertion failure
     */
    static void waitOnLatchNegative(CountDownLatch latch, String failMsg) {
        try {
            if (latch.await(5, TimeUnit.SECONDS)) {
                fail(failMsg);
            }
        } catch (InterruptedException ex) {
            fail(ex);
        }
    }


    /**
     * A subscriber of data chunk that accumulates bytes to a single String.
     */
    static final class PartContentSubscriber implements Subscriber<DataChunk> {

        private final StringBuilder sb = new StringBuilder();
        private final CompletableFuture<String> future =
                new CompletableFuture<>();

        @Override
        public void onSubscribe(Subscription subscription) {
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(DataChunk item) {
            sb.append(new String(item.bytes()));
        }

        @Override
        public void onError(Throwable ex) {
            future.completeExceptionally(ex);
        }

        @Override
        public void onComplete() {
            future.complete(sb.toString());
        }

        CompletionStage<String> content() {
            return future;
        }
    }

    /**
     * A publisher that publishes data chunks from a predefined set of byte
     * arrays.
     */
    static final class DataChunkPublisher implements Publisher<DataChunk> {

        private final Queue<DataChunk> queue = new LinkedList<>();
        private long requested;
        private boolean delivering;
        private boolean canceled;
        private boolean complete;

        public DataChunkPublisher(byte[]... chunksData) {
            canceled = false;
            requested = 0;
            for (byte[] chunkData : chunksData) {
                queue.add(DataChunk.create(chunkData));
            }
        }

        @Override
        public void subscribe(Subscriber<? super DataChunk> subscriber) {
            subscriber.onSubscribe(new Flow.Subscription() {
                @Override
                public void request(long n) {
                    if (n <= 0 || canceled || complete) {
                        return;
                    }
                    requested += n;
                    if (delivering) {
                        return;
                    }
                    delivering = true;
                    while (!complete && requested > 0) {
                        DataChunk chunk = queue.poll();
                        if (chunk != null) {
                            requested--;
                            if (queue.isEmpty()) {
                                complete = true;
                            }
                            subscriber.onNext(chunk);
                        }
                    }
                    delivering = false;
                    if (complete) {
                        subscriber.onComplete();
                    }
                }

                @Override
                public void cancel() {
                    canceled = true;
                }
            });
        }
    }
}