/// Helper to create a peer-to-peer connection pair using Unix socket
pub(crate) async fn create_p2p_connection() -> (zbus::Connection, zbus::Connection) {
    let guid = zbus::Guid::generate();
    let (p0, p1) = tokio::net::UnixStream::pair().unwrap();

    let (client_conn, server_conn) = tokio::try_join!(
        // Client
        zbus::connection::Builder::unix_stream(p0).p2p().build(),
        // Server
        zbus::connection::Builder::unix_stream(p1)
            .server(guid)
            .unwrap()
            .p2p()
            .build(),
    )
    .unwrap();

    (server_conn, client_conn)
}
