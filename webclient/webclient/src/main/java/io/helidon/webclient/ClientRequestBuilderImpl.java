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
package io.helidon.webclient;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import io.helidon.common.GenericType;
import io.helidon.common.context.Context;
import io.helidon.common.http.DataChunk;
import io.helidon.common.http.HashParameters;
import io.helidon.common.http.Headers;
import io.helidon.common.http.Http;
import io.helidon.common.http.HttpRequest;
import io.helidon.common.http.MediaType;
import io.helidon.common.http.Parameters;
import io.helidon.common.reactive.Flow;
import io.helidon.common.reactive.Single;
import io.helidon.media.common.MessageBodyReadableContent;
import io.helidon.media.common.MessageBodyReader;
import io.helidon.media.common.MessageBodyWriteableContent;
import io.helidon.media.jsonp.common.JsonProcessing;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.util.AttributeKey;

import static io.helidon.webclient.NettyClient.EVENT_GROUP;

/**
 * TODO Javadoc
 */
class ClientRequestBuilderImpl implements ClientRequestBuilder {
    private static final Map<String, Integer> SUPPORTED_PROTOCOLS = new HashMap<>();
    static final AttributeKey<ClientRequest> REQUEST = AttributeKey.valueOf("request");

    static {
        SUPPORTED_PROTOCOLS.put("http", 80);
        SUPPORTED_PROTOCOLS.put("https", 443);
    }

    private final Map<String, Object> properties;
    private final LazyValue<NioEventLoopGroup> eventGroup;
    private final ClientConfiguration configuration;
    private final Http.Method method;
    private final ClientRequestHeaders headers;
    private final Parameters queryParams;
    private final List<ClientContentHandler> clientContentHandlers;

    private URI uri;
    private Http.Version httpVersion;
    private Context context;
    private Proxy proxy;
    private String fragment;
    private int redirectionCount;
    private RequestConfiguration requestConfiguration;

    private ClientRequestBuilderImpl(LazyValue<NioEventLoopGroup> eventGroup,
                                     ClientConfiguration configuration,
                                     Http.Method method) {
        this.properties = new HashMap<>();
        this.eventGroup = eventGroup;
        this.configuration = configuration;
        this.method = method;
        this.headers = new ClientRequestHeadersImpl();
        this.queryParams = new HashParameters();
        this.clientContentHandlers = new ArrayList<>();
        this.httpVersion = Http.Version.V1_1;
        this.fragment = "";
        this.redirectionCount = 0;
    }

    public static ClientRequestBuilder create(LazyValue<NioEventLoopGroup> eventGroup,
                                              ClientConfiguration configuration,
                                              Http.Method method) {
        return new ClientRequestBuilderImpl(eventGroup, configuration, method);
    }

    public static ClientRequestBuilder create(ClientRequestBuilder.ClientRequest clientRequest) {
        ClientRequestBuilderImpl builder = new ClientRequestBuilderImpl(EVENT_GROUP,
                                                                        clientRequest.configuration(),
                                                                        (Http.Method) clientRequest.method());
        builder.headers(clientRequest.headers());
        builder.queryParams(clientRequest.queryParams());
        builder.properties.putAll(clientRequest.properties());
        builder.uri = clientRequest.uri();
        builder.httpVersion = clientRequest.version();
        builder.proxy = clientRequest.proxy();
        builder.fragment = clientRequest.fragment();
        builder.redirectionCount = clientRequest.redirectionCount() + 1;
        int maxRedirects = builder.configuration.maxRedirects();
        if (builder.redirectionCount > maxRedirects) {
            throw new ClientException("Max number of redirects extended! (" + maxRedirects + ")");
        }
        return builder;
    }

    @Override
    public ClientRequestBuilder uri(String uri) {
        this.uri = URI.create(uri);
        return this;
    }

    @Override
    public ClientRequestBuilder uri(URL url) {
        try {
            this.uri = url.toURI();
        } catch (URISyntaxException e) {
            throw new ClientException("Failed to create URI from URL", e);
        }
        return this;
    }

    @Override
    public ClientRequestBuilder uri(URI uri) {
        this.uri = uri;
        return this;
    }

    @Override
    public ClientRequestBuilder property(String propertyName, Object propertyValue) {
        properties.put(propertyName, propertyValue);
        return this;
    }

    @Override
    public ClientRequestBuilder context(Context context) {
        this.context = context;
        return this;
    }

    @Override
    public ClientRequestBuilder header(String header, String... values) {
        headers.put(header, values);
        return this;
    }

    @Override
    public ClientRequestHeaders headers() {
        return headers;
    }

    @Override
    public ClientRequestBuilder queryParam(String name, String... values) {
        queryParams.add(name, values);
        return this;
    }

    @Override
    public ClientRequestBuilder proxy(Proxy proxy) {
        this.proxy = proxy;
        return this;
    }

    @Override
    public ClientRequestBuilder headers(Headers headers) {
        this.headers.putAll(headers);
        return this;
    }

    @Override
    public ClientRequestBuilder queryParams(Parameters queryParams) {
        Objects.requireNonNull(queryParams);
        queryParams.toMap().forEach((name, params) -> queryParam(name, params.toArray(new String[0])));
        return this;
    }

    @Override
    public ClientRequestBuilder register(ClientContentHandler<?> handler) {
        this.clientContentHandlers.add(handler);
        return this;
    }

    @Override
    public ClientRequestBuilder httpVersion(Http.Version httpVersion) {
        this.httpVersion = httpVersion;
        return this;
    }

    @Override
    public ClientRequestBuilder fragment(String fragment) {
        this.fragment = fragment;
        return this;
    }

    @Override
    public ClientRequestBuilder path(HttpRequest.Path path) {
        return null;
    }

    @Override
    public ClientRequestBuilder contentType(MediaType mediaType) {
        this.headers.contentType(mediaType);
        return this;
    }

    @Override
    public ClientRequestBuilder contentLength(long length) {
        this.headers.contentLength(length);
        return this;
    }

    @Override
    public ClientRequestBuilder ifModifiedSince(ZonedDateTime time) {
        return null;
    }

    @Override
    public ClientRequestBuilder ifNoneMatch(String... etags) {
        return null;
    }

    @Override
    public ClientRequestBuilder accept(MediaType... mediaTypes) {
        Arrays.stream(mediaTypes).forEach(headers::addAccept);
        return this;
    }

    @Override
    public CompletionStage<ClientResponse> redirect() {
        return request(ClientResponse.class);
    }

    @Override
    public <T> CompletionStage<T> request(Class<T> responseType) {
        return request(GenericType.create(responseType));
    }

    @Override
    public <T> CompletionStage<T> request(GenericType<T> responseType) {
        return invoke(Single.empty(), responseType);
    }

    @Override
    public CompletionStage<ClientResponse> submit() {
        return submit((Object) null);
    }

    @Override
    public <T> CompletionStage<T> submit(Flow.Publisher<DataChunk> requestEntity, Class<T> responseType) {
        return invoke(requestEntity, GenericType.create(responseType));
    }

    @Override
    public <T> CompletionStage<T> submit(Object requestEntity, Class<T> responseType) {
        MessageBodyWriteableContent writeableContent = MessageBodyWriteableContent.create(requestEntity, this.headers);
        writeableContent.registerWriter(JsonProcessing.create().newWriter());
        Flow.Publisher<DataChunk> dataChunkPublisher = writeableContent.toPublisher(null);
        return invoke(dataChunkPublisher, GenericType.create(responseType));
    }

    @Override
    public CompletionStage<ClientResponse> submit(Flow.Publisher<DataChunk> requestEntity) {
        return submit(requestEntity, ClientResponse.class);
    }

    @Override
    public CompletionStage<ClientResponse> submit(Object requestEntity) {
        return submit(requestEntity, ClientResponse.class);
    }

    Http.Method method() {
        return method;
    }

    Http.Version httpVersion() {
        return httpVersion;
    }

    URI uri() {
        return uri;
    }

    Parameters queryParams() {
        return queryParams;
    }

    String query() {
        String queries = "";
        for (Map.Entry<String, List<String>> entry : queryParams.toMap().entrySet()) {
            for (String value : entry.getValue()) {
                String query = entry.getKey() + "=" + value;
                queries = queries.isEmpty() ? query : queries + "&" + query;
            }
        }
        return queries;
    }

    String fragment() {
        return fragment;
    }

    RequestConfiguration requestConfiguration() {
        return requestConfiguration;
    }

    Map<String, Object> properties() {
        return properties;
    }

    Proxy proxy() {
        return proxy;
    }

    int redirectionCount() {
        return redirectionCount;
    }

    @SuppressWarnings("unchecked")
    private <T> CompletionStage<T> invoke(Flow.Publisher<DataChunk> requestEntity, GenericType<T> responseType) {
        //TODO co s navratovym typem?
        clientContentHandlers.forEach(clientContentHandler -> clientContentHandler.writer(this));
        URI uri = prepareFinalURI();

        DefaultHttpRequest request = new DefaultHttpRequest(toNettyHttpVersion(httpVersion),
                                                            toNettyMethod(method),
                                                            uri.toASCIIString());
        setRequestHeaders(request.headers());

        requestConfiguration = RequestConfiguration.builder(uri).update(configuration).build();
        ClientRequestImpl clientRequest = new ClientRequestImpl(this);

        CompletableFuture<ClientResponse> result = new CompletableFuture<>();

        EventLoopGroup group = eventGroup.get();
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(group)
                .channel(NioSocketChannel.class)
                .handler(new NettyClientInitializer(requestConfiguration, result))
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, (int) configuration.connectTimeout().toMillis());

        ChannelFuture channelFuture = bootstrap.connect(uri.getHost(), uri.getPort());
        channelFuture.addListener((ChannelFutureListener) future -> {
            Throwable cause = future.cause();
            if (null == cause) {
                RequestContentSubscriber requestContentSubscriber = new RequestContentSubscriber(request,
                                                                                                 channelFuture.channel(),
                                                                                                 result);
                requestEntity.subscribe(requestContentSubscriber);
            } else {
                result.completeExceptionally(new ClientException(uri.toString(), cause));
            }
        });
        channelFuture.channel().attr(REQUEST).set(clientRequest);
        if (responseType.rawType().equals(ClientResponse.class)) {
            return (CompletionStage<T>) result;
        } else {
            return result.thenApply(clientResponse -> getContentFromClientResponse(responseType.rawType(),
                                                                                   clientRequest,
                                                                                   clientResponse))
                    .thenCompose(content -> content.as(responseType));
        }
    }

    private void setRequestHeaders(HttpHeaders headers) {
        headers.set(HttpHeaderNames.HOST, uri.getHost());
        headers.set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
        headers.set(HttpHeaderNames.ACCEPT_ENCODING, HttpHeaderValues.GZIP);
        try {
            Map<String, List<String>> cookieHeaders = this.configuration.cookieManager().get(uri, new HashMap<>());
            List<String> cookies = new ArrayList<>(cookieHeaders.get(Http.Header.COOKIE));
            cookies.addAll(this.headers.values(Http.Header.COOKIE));
            if (!cookies.isEmpty()) {
                headers.add(Http.Header.COOKIE, String.join("; ", cookies));
            }
        } catch (IOException e) {
            throw new ClientException("An error occurred while setting cookies.", e);
        }
        this.configuration.headers().toMap().forEach(headers::add);
        this.headers.toMap().forEach(headers::add);
    }

    private URI prepareFinalURI() {
        String base = resolveURIBase();
        String queries = query();
        return URI.create(base + (queries.isEmpty() ? "" : "?" + queries)
                                  + (fragment.isEmpty() ? "" : "#" + fragment));
    }

    private String resolveURIBase() {
        String scheme = Optional.ofNullable(this.uri.getScheme())
                .orElseThrow(() -> new ClientException("URI: " + uri + " does not have schema specified."));
        Integer port = uri.getPort() > -1 ? uri.getPort() : SUPPORTED_PROTOCOLS.get(scheme);
        if (port == null) {
            throw new ClientException("Client could not get port for schema " + scheme + ". "
                                              + "Please specify correct port to use.");
        }
        return scheme + "://" + uri.getHost() + ":" + port + uri.getPath();
    }

    private HttpMethod toNettyMethod(Http.Method method) {
        return HttpMethod.valueOf(method.name());
    }

    private HttpVersion toNettyHttpVersion(Http.Version version) {
        return HttpVersion.valueOf(version.value());
    }

    private <T> MessageBodyReadableContent getContentFromClientResponse(Class<T> responseType, ClientRequest clientRequest,
                                                                        ClientResponse clientResponse) {
        MessageBodyReadableContent content = clientResponse.content();
        content.registerReader(JsonProcessing.create().newReader());

        //TODO neudelat to radeji jako generic misto class?
        clientContentHandlers.stream()
                .filter(clientContentHandler -> clientContentHandler.supports(responseType))
                .forEach(clientContentHandler -> {
                    Optional<MessageBodyReader<T>> reader = clientContentHandler.reader(clientRequest, clientResponse);
                    reader.ifPresent(content::registerReader);
                });
        return content;
    }
}
