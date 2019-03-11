package io.helidon.microprofile.restClient;

import java.io.IOException;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

/**
 * Created by David Kral.
 */
public class TestFilter implements ClientRequestFilter {
    @Context
    HttpHeaders headers;

    @Override
    public void filter(ClientRequestContext clientRequestContext) throws IOException {
        //TODO smazat
        JsonObjectBuilder allClientHeaders = Json.createObjectBuilder();
        MultivaluedMap<String,String> clientHeaders = headers.getRequestHeaders();
        for (String headerName : clientHeaders.keySet()) {
            allClientHeaders.add(headerName, clientHeaders.getFirst(headerName));
        }
        clientRequestContext.abortWith(Response.ok(allClientHeaders.build()).build());

    }
}
