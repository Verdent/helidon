/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
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

package io.helidon.declarative.tests.grpc;

import java.util.Iterator;

import io.helidon.webserver.grpc.RpcServer;

@RpcServer.Endpoint
@RpcServer.ServiceName("ClientStreamingShapes")
class ClientStreamingShapesEndpoint {
    private static volatile int iterableCount;
    private static volatile int iteratorCount;

    static void reset() {
        iterableCount = 0;
        iteratorCount = 0;
    }

    static int iterableCount() {
        return iterableCount;
    }

    static int iteratorCount() {
        return iteratorCount;
    }

    @RpcServer.ClientStreaming("JoinIterable")
    TextMessages.TextMessage joinIterable(Iterable<TextMessages.TextMessage> requests) {
        return message("ITERABLE:" + joinTexts(requests));
    }

    @RpcServer.ClientStreaming("JoinIterator")
    TextMessages.TextMessage joinIterator(Iterator<TextMessages.TextMessage> requests) {
        return message("ITERATOR:" + joinTexts(requests));
    }

    @RpcServer.ClientStreaming("CountIterable")
    void countIterable(Iterable<TextMessages.TextMessage> requests) {
        iterableCount = countRequests(requests);
    }

    @RpcServer.ClientStreaming("CountIterator")
    void countIterator(Iterator<TextMessages.TextMessage> requests) {
        iteratorCount = countRequests(requests);
    }

    private static String joinTexts(Iterable<TextMessages.TextMessage> requests) {
        StringBuilder result = new StringBuilder();
        for (TextMessages.TextMessage request : requests) {
            if (result.length() > 0) {
                result.append(' ');
            }
            result.append(request.getText());
        }
        return result.toString();
    }

    private static String joinTexts(Iterator<TextMessages.TextMessage> requests) {
        StringBuilder result = new StringBuilder();
        while (requests.hasNext()) {
            if (result.length() > 0) {
                result.append(' ');
            }
            result.append(requests.next().getText());
        }
        return result.toString();
    }

    private static int countRequests(Iterable<TextMessages.TextMessage> requests) {
        int count = 0;
        for (TextMessages.TextMessage ignored : requests) {
            count++;
        }
        return count;
    }

    private static int countRequests(Iterator<TextMessages.TextMessage> requests) {
        int count = 0;
        while (requests.hasNext()) {
            requests.next();
            count++;
        }
        return count;
    }

    private static TextMessages.TextMessage message(String text) {
        return TextMessages.TextMessage.newBuilder()
                .setText(text)
                .build();
    }
}
