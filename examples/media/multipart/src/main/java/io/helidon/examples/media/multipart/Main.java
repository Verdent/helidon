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
package io.helidon.examples.media.multipart;

import io.helidon.common.http.Http;
import io.helidon.webserver.Routing;
import io.helidon.webserver.ServerConfiguration;
import io.helidon.webserver.StaticContentSupport;
import io.helidon.webserver.WebServer;

/**
 * This application serves a simple HTML with a file-upload form that posts to
 * an endpoint that accepts handles multipart requests.
 */
public final class Main {

    private Main() {
    }

    /**
     * Creates new {@link Routing}.
     *
     * @return the new instance
     */
    static Routing createRouting() {
        return Routing.builder()
                .any("/", (req, res) -> {
                    // showing the capability to run on any path, and
                    // redirecting from root
                    res.status(Http.Status.MOVED_PERMANENTLY_301);
                    res.headers().put(Http.Header.LOCATION, "/ui");
                    res.send();
                })
                .register("/ui", StaticContentSupport.builder("WEB")
                        .welcomeFileName("index.html")
                        .build())
                .register("/upload", new FileUploadService())
                .build();
    }

    /**
     * A java main class.
     *
     * @param args command line arguments.
     */
    public static void main(String[] args) {
        ServerConfiguration config = ServerConfiguration.builder()
                .port(8080)
                .build();
        WebServer server = WebServer.create(config, createRouting());

        // Start the server and print some info.
        server.start().thenAccept(ws -> {
            System.out.println("WEB server is up! http://localhost:" + ws.port());
        });

        // Server threads are not demon. NO need to block. Just react.
        server.whenShutdown()
                .thenRun(() -> System.out.println("WEB server is DOWN. Good bye!"));

    }
}