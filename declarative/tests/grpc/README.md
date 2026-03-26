Helidon Declarative gRPC Example
================================

This module is the small declarative gRPC example application for the current feature set.
It doubles as the runtime regression suite for the generated server and client code.

What it demonstrates
--------------------

- declarative gRPC server registration
- typed declarative gRPC client injection
- all four RPC interaction styles
- blocking unary and server-streaming shortcut shapes with explicit functional coverage
- service-level and method-level gRPC interceptors
- entry-point interception, metrics, and tracing on gRPC methods
- listener, service-name, config-key, static named-client, and default-client configuration

Key files
---------

- `src/main/java/io/helidon/declarative/tests/grpc/TextServiceEndpoint.java` - basic endpoint covering unary and all streaming text operations
- `src/main/java/io/helidon/declarative/tests/grpc/TextServiceClient.java` - typed client for the same contract
- `src/main/java/io/helidon/declarative/tests/grpc/UnaryShapesEndpoint.java` - dedicated endpoint covering blocking unary and no-request server-streaming shortcut forms
- `src/main/java/io/helidon/declarative/tests/grpc/UnaryShapesClient.java` - typed client for the shortcut endpoint, including no-arg unary and server-streaming methods
- `src/main/java/io/helidon/declarative/tests/grpc/ConfiguredTextServiceEndpoint.java` - endpoint using configuration placeholders
- `src/main/java/io/helidon/declarative/tests/grpc/ConfiguredTextServiceClient.java` - client using configurable service name and static named client selection
- `src/main/java/io/helidon/declarative/tests/grpc/DefaultGrpcClient.java` - unnamed registry client used by generated clients as the default fallback
- `src/main/java/io/helidon/declarative/tests/grpc/ConfigBackedTextServiceClient.java` - client using `configKey` and a `GrpcClient` config subtree
- `src/main/java/io/helidon/declarative/tests/grpc/TextServiceClientInterceptor.java` - client-wide gRPC interceptor
- `src/main/java/io/helidon/declarative/tests/grpc/TextServiceServerUpperInterceptor.java` - method-specific server interceptor
- `src/main/java/io/helidon/declarative/tests/grpc/Main.java` - application bootstrap
- `src/main/resources/application.yaml` - listener and client configuration
- `src/test/java/io/helidon/declarative/tests/grpc/DeclarativeGrpcUnaryShapesTest.java` - explicit functional tests for the blocking shortcut forms

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

- `@RpcServer.Unary` supports observer-based methods, no-request unary methods, direct response return, and unary methods that implicitly respond with `com.google.protobuf.Empty`
- `@RpcServer.ServerStreaming` supports observer-based methods, no-request server-streaming methods, and `Stream<ResponseT>` return
- `@RpcServer.ClientStreaming` stays on the explicit `StreamObserver<ResponseT>` response parameter
- `@RpcServer.Bidirectional` stays on the explicit `StreamObserver` form

Generated typed clients in this module also support no-arg unary and no-arg server-streaming methods. Those calls use `com.google.protobuf.Empty` on the wire.

Validation
----------

The narrow validation command for this module is:

```bash
mvn -Ptests -pl :helidon-declarative-tests-grpc -am test
```
