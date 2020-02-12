/*
 * Copyright (c) 2018 Oracle and/or its affiliates. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package io.helidon.rest.client.example.basic;

import java.nio.file.Path;

import io.helidon.webclient.ClientResponse;
import io.helidon.webclient.FileSubscriber;
import io.helidon.webclient.WebClient;

/**
 * TODO javadoc.
 */
public class UploadAndDownloadExample {
    public static void main(String[] args) {

    }

    void upload(Path filePath, String uri) {
        //EDIT: zaregistrovat defaulty pokud nic nezadano a jinak tam nahodit empty pokud neco chce. Registrovat pres metodu }??
//        WebClient client = WebClient.mediaSupport(MediaSupport.builder()
//                                                          .registerDefaults()
//                                                          .registerWriter(MultipartBodyWriter.get())
//                                                          .build()).create();
//
//
//        client.put()
//                .uri(uri)
//                .submit(WriteableMultiPart.create(Paths.get("/foo")))
//                .submit(Paths.get("some"))
//                .submit(FilePublisher.create(filePath))
//                .thenApply(ClientResponse::status)
//                .thenAccept(System.out::println);
    }

    void download(String uri, Path filePath) {
        WebClient client = WebClient.create();
        FileSubscriber sub = FileSubscriber.create(filePath);

        client.get()
                .uri(uri)
                .request()
                .thenApply(ClientResponse::content)
                .thenAccept(sub::subscribeTo)
                .thenAccept(o -> System.out.println("Download completed"));
    }
}
