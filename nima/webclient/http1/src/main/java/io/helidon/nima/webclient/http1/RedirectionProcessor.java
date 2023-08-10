package io.helidon.nima.webclient.http1;

import java.net.URI;

import io.helidon.common.buffers.BufferData;
import io.helidon.common.http.Http;
import io.helidon.nima.webclient.api.ClientUri;

class RedirectionProcessor {

    private Http1ClientResponseImpl invokeWithFollowRedirectsEntity(Http1ClientRequestImpl request, Object entity) {
        //Request object which should be used for invoking the next request. This will change in case of any redirection.
        Http1ClientRequestImpl clientRequest = request;
        //Entity to be sent with the request. Will be changed when redirect happens to prevent entity sending.
        Object entityToBeSent = entity;
        boolean sendingEntity = true;
        for (int i = 0; i < request.maxRedirects(); i++) {
            Http1ClientResponseImpl clientResponse = clientRequest.invokeRequestWithEntity(entityToBeSent);
            int code = clientResponse.status().code();
            if (code < 300 || code >= 400) {
                return clientResponse;
            } else if (!clientResponse.headers().contains(Http.Header.LOCATION)) {
                throw new IllegalStateException("There is no " + Http.Header.LOCATION + " header present in the response! "
                                                        + "It is not clear where to redirect.");
            }
            String redirectedUri = clientResponse.headers().get(Http.Header.LOCATION).value();
            URI newUri = URI.create(redirectedUri);
            ClientUri redirectUri = ClientUri.create(newUri);

            if (newUri.getHost() == null) {
                //To keep the information about the latest host, we need to use uri from the last performed request
                //Example:
                //request -> my-test.com -> response redirect -> my-example.com
                //new request -> my-example.com -> response redirect -> /login
                //with using the last request uri host etc, we prevent my-test.com/login from happening
                ClientUri resolvedUri = clientRequest.resolvedUri();
                redirectUri.scheme(resolvedUri.scheme());
                redirectUri.host(resolvedUri.host());
                redirectUri.port(resolvedUri.port());
            }
            //Method and entity is required to be the same as with original request with 307 and 308 requests
            if (clientResponse.status() == Http.Status.TEMPORARY_REDIRECT_307
                    || clientResponse.status() == Http.Status.PERMANENT_REDIRECT_308) {
                clientRequest = new Http1ClientRequestImpl(clientRequest,
                                                           clientRequest.method(),
                                                           redirectUri,
                                                           request.properties());
            } else {
                //It is possible to change to GET and send no entity with all other redirect codes
                entityToBeSent = BufferData.EMPTY_BYTES; //We do not want to send entity after this redirect
                clientRequest = new Http1ClientRequestImpl(clientRequest, Http.Method.GET, redirectUri, request.properties());
            }
        }
        throw new IllegalStateException("Maximum number of request redirections ("
                                                + request.maxRedirects() + ") reached.");
    }

}
