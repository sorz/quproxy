use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ClientAddr(pub(crate) SocketAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RemoteAddr(pub(crate) SocketAddr);

impl From<SocketAddr> for ClientAddr {
    fn from(addr: SocketAddr) -> Self {
        Self(addr)
    }
}

impl From<SocketAddr> for RemoteAddr {
    fn from(addr: SocketAddr) -> Self {
        Self(addr)
    }
}
