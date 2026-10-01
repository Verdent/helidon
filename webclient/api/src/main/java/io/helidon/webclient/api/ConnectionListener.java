/*
 * Copyright (c) 2023, 2026 Oracle and/or its affiliates.
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
package io.helidon.webclient.api;

import java.io.IOException;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.util.Objects;

import javax.net.ssl.SSLSession;

/**
 * Socket callbacks run when the client connection is first established, before TLS or HTTP application traffic is sent.
 * They can be used for protocols such as the HAProxy Proxy Protocol, which send data before the TLS handshake.
 * The TLS callback runs after a successful handshake, before an HTTP request is sent over that TLS connection.
 */
public interface ConnectionListener {
    /**
     * Returns a {@link ConnectionListener} which does nothing.
     * @return The no-op listener.
     */
    static ConnectionListener createNoop() {
        return new DefaultConnectionListener();
    }

    /**
     * Returns a {@link ConnectionListener} which writes bytes to the socket once the socket is connected.
     * @param bytes The bytes to write.
     * @return The listener which will write the given bytes to the socket.
     */
    static ConnectionListener createWriteOnConnect(byte[] bytes) {
        return new BytesWritingConnectionListener(bytes);
    }

    /**
     * Called when the given {@link Socket} connection has been established and {@link io.helidon.common.socket.SocketOptions}
     * applied, but before any TLS or HTTP application traffic has been sent.
     * @param socketInfo The newly connected socket.
     * @throws IOException if an I/O error occurs
     */
    void socketConnected(ConnectedSocketInfo socketInfo) throws IOException;

    /**
     * Called when the given {@link SocketChannel} connection has been established and
     * {@link io.helidon.common.socket.SocketOptions} applied, but before any TLS or HTTP application traffic has been sent.
     * @param socketInfo The newly connected socket channel.
     * @throws IOException if an I/O error occurs
     */
    void socketChannelConnected(ConnectedSocketChannelInfo socketInfo) throws IOException;

    /**
     * Called after a TLS handshake succeeds, before an HTTP request is sent over the TLS connection.
     * This callback is not invoked when a connection is reused from a pool. Throwing an exception rejects and closes
     * the connection.
     *
     * @param session the established TLS session
     */
    default void tlsHandshakeCompleted(SSLSession session) {
        Objects.requireNonNull(session, "session");
    }
}
