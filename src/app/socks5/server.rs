use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub(crate) struct SocksServer {
    pub(crate) name: String,
    pub(crate) udp_addr: SocketAddr,
}

impl SocksServer {
    pub(crate) fn new(udp_addr: SocketAddr, name: Option<String>) -> Self {
        let name = name.unwrap_or_else(|| udp_addr.to_string());
        Self { name, udp_addr }
    }
}
