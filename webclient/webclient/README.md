Web Client

Netty based HTTP client.


Features (tick to mark as implemented):


[ ] Client configuration
    [ ] Event loop
    [ ] Timeouts
    [ ] Follow redirects
    [ ] User agent
    [ ] Cookies
        [ ] Use a shared cookie store (for a single client instance - security!!!)
        [ ] Use automated approach (add to store, retrieve from it)
        [ ] Default cookies (add to every request)
    [ ] Default headers (add to every request)
    [ ] Services (extensions)
        [ ] Exclude implementations (Helidon Service loader)
        [ ] Configuration support of services (such as service registry, metrics)
    [ ] Proxy (http, https, no-proxy, type (http/socks), security?)
    [ ] SSL
        [ ] enabled/disabled (explicitly disable calls to SSL sites,)
        [ ] client-cert support (keystore, password, type)
        [ ] custom hostname verifier (using a service loader, named based)- @default and @none as reserved names
        [ ] trustore (type, location, password)
    [ ] Targets - override configuration per target (such as in security outbound)
[ ] Client implementation
    [ ] simple
        [ ] GET
        [ ] POST
        [ ] PUT
        [ ] DELETE
        [ ] HEAD
        [ ] OPTIONS
    [ ] reactive response processing
    [ ] reactive request processing
    [ ] content type support (Class<T> and GenericType<T>)
[ ] Security
[ ] Metrics
[ ] Tracing
