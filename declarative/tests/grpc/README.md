Helidon Declarative gRPC Example
================================

This module is the small declarative gRPC example application for the current feature set.
It doubles as the runtime regression suite for the generated server and client code.

What it demonstrates
--------------------

- declarative gRPC server registration
- typed declarative gRPC client injection
- all four RPC interaction styles
- simplified unary, server-streaming, and client-streaming server method shapes with explicit functional coverage
- service-level and method-level gRPC interceptors
- entry-point interception, metrics, and tracing on gRPC methods
- listener, service-name, config-key, static named-client, and default-client configuration

Key files
---------

- `src/main/java/io/helidon/declarative/tests/grpc/TextServiceEndpoint.java` - basic endpoint covering unary, streaming, and future-backed client-streaming text operations
- `src/main/java/io/helidon/declarative/tests/grpc/TextServiceClient.java` - typed client for the same contract
- `src/main/java/io/helidon/declarative/tests/grpc/UnaryShapesEndpoint.java` - dedicated endpoint covering the unary shortcut forms
- `src/main/java/io/helidon/declarative/tests/grpc/UnaryShapesClient.java` - typed client for the unary shortcut endpoint
- `src/main/java/io/helidon/declarative/tests/grpc/ConfiguredTextServiceEndpoint.java` - endpoint using configuration placeholders
- `src/main/java/io/helidon/declarative/tests/grpc/ConfiguredTextServiceClient.java` - client using configurable service name and static named client selection
- `src/main/java/io/helidon/declarative/tests/grpc/DefaultGrpcClient.java` - unnamed registry client used by generated clients as the default fallback
- `src/main/java/io/helidon/declarative/tests/grpc/ConfigBackedTextServiceClient.java` - client using `configKey` and a `GrpcClient` config subtree
- `src/main/java/io/helidon/declarative/tests/grpc/TextServiceClientInterceptor.java` - client-wide gRPC interceptor
- `src/main/java/io/helidon/declarative/tests/grpc/TextServiceServerUpperInterceptor.java` - method-specific server interceptor
- `src/main/java/io/helidon/declarative/tests/grpc/Main.java` - application bootstrap
- `src/main/resources/application.yaml` - listener and client configuration
- `src/test/java/io/helidon/declarative/tests/grpc/DeclarativeGrpcUnaryShapesTest.java` - explicit functional tests for the unary shortcut forms

Minimal shape
-------------

```java
@RpcServer.Endpoint
@RpcServer.ServiceName("example.Greeter")
class GreeterEndpoint {
    @RpcServer.Proto
    Descriptors.FileDescriptor proto() {
        return Greeter.getDescriptor();
    }

    @RpcServer.Unary("SayHello")
    HelloReply sayHello(HelloRequest request) {
        return HelloReply.newBuilder()
                .setMessage("Hello " + request.getName())
                .build();
    }
}

@RpcClient.Endpoint(value = "${greeter.uri:http://localhost:8080}",
                    configKey = "greeter.client")
@RpcClient.ServiceName("example.Greeter")
interface GreeterClient {
    @RpcClient.Unary("SayHello")
    HelloReply sayHello(HelloRequest request);
}
```

No explicit service scope is needed on the endpoint. If you do not declare one, the endpoint is treated as a singleton service by default.

Supported server shapes:

- `@RpcServer.Unary` supports observer-based methods, direct response return, `CompletionStage` / `CompletableFuture` response return, and `CompletableFuture<ResponseT>` response parameters
- `@RpcServer.ServerStreaming` supports observer-based methods and `Stream<ResponseT>` return
- `@RpcServer.ClientStreaming` supports both the explicit `StreamObserver<ResponseT>` response parameter and the simplified `CompletableFuture<ResponseT>` response parameter
- `@RpcServer.Bidirectional` stays on the explicit `StreamObserver` form

Validation
----------

The narrow validation command for this module is:

```bash
mvn -Ptests -pl :helidon-declarative-tests-grpc -am test
```
