use bytes::Bytes;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct ClientAddr(pub(crate) SocketAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct RemoteAddr(pub(crate) SocketAddr);

impl From<SocketAddr> for ClientAddr {
    fn from(addr: SocketAddr) -> Self {
        Self(canonicalize_socket_addr(addr))
    }
}

impl From<SocketAddr> for RemoteAddr {
    fn from(addr: SocketAddr) -> Self {
        Self(canonicalize_socket_addr(addr))
    }
}

pub(crate) type UdpPackets = (ClientAddr, RemoteAddr, Box<[Bytes]>);

fn canonicalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => addr,
        SocketAddr::V6(addr6) => {
            if let Some(ip4) = addr6.ip().to_ipv4() {
                (ip4, addr6.port()).into()
            } else {
                addr
            }
        }
    }
}
