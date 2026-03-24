Helidon Declarative gRPC Example
================================

This module is the small declarative gRPC example application for the current feature set.
It doubles as the runtime regression suite for the generated server and client code.

What it demonstrates
--------------------

- declarative gRPC server registration
- typed declarative gRPC client injection
- all four RPC interaction styles
- entry-point interception, metrics, and tracing on gRPC methods
- listener, service-name, and named-client configuration through annotation expressions

Key files
---------

- `src/main/java/io/helidon/declarative/tests/grpc/TextServiceEndpoint.java` - basic endpoint covering unary and streaming text operations
- `src/main/java/io/helidon/declarative/tests/grpc/TextServiceClient.java` - typed client for the same contract
- `src/main/java/io/helidon/declarative/tests/grpc/ConfiguredTextServiceEndpoint.java` - endpoint using configuration placeholders
- `src/main/java/io/helidon/declarative/tests/grpc/ConfiguredTextServiceClient.java` - client using configurable service name and named client selection
- `src/main/java/io/helidon/declarative/tests/grpc/Main.java` - application bootstrap
- `src/main/resources/application.yaml` - listener and client configuration

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
    void sayHello(HelloRequest request, StreamObserver<HelloReply> observer) {
        observer.onNext(HelloReply.newBuilder()
                                .setMessage("Hello " + request.getName())
                                .build());
        observer.onCompleted();
    }
}

@RpcClient.Endpoint("${greeter.uri:http://localhost:8080}")
@RpcClient.ServiceName("example.Greeter")
interface GreeterClient {
    @RpcClient.Unary("SayHello")
    HelloReply sayHello(HelloRequest request);
}
```

Validation
----------

The narrow validation command for this module is:

```bash
mvn -Ptests -pl :helidon-declarative-tests-grpc -am test
```
