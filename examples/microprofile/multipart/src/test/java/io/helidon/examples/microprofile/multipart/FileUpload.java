/*
 * Copyright (c) 2022 Oracle and/or its affiliates.
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

package io.helidon.examples.microprofile.multipart;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;
import org.glassfish.jersey.media.multipart.MultiPart;

/**
 * TODO javadoc
 */
@Path("/somePath")
public interface FileUpload {

    @POST
    @ClientHeaderParam(name="Content-Type", value="multipart/form-data; boundary=100000")
    @ClientHeaderParam(name="Authorization", value="Basic Y2didV9lY3BfZGV2b3BzX3d3X2dycDpFLLY3BAZGV2b3BzMjAyMg==")
    Response uploadFile(MultiPart multiPart);

}
