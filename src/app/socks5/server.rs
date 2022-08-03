use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use derivative::Derivative;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::app::ServerStatus;

#[derive(Derivative)]
#[derivative(Debug, Hash, PartialEq, Eq)]
pub(crate) struct SocksServer {
    pub(crate) name: String,
    pub(crate) udp_addr: SocketAddr,

    #[derivative(PartialEq = "ignore")]
    #[derivative(Hash = "ignore")]
    pub(crate) status: ServerStatus,
}

impl SocksServer {
    pub(crate) fn new(udp_addr: SocketAddr, name: Option<String>) -> Self {
        let name = name.unwrap_or_else(|| udp_addr.to_string());
        Self {
            name,
            udp_addr,
            status: Default::default(),
        }
    }
}

macro_rules! io_error {
    ($msg:expr) => {
        return Err(io::Error::new(io::ErrorKind::Other, $msg))
    };
}

const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SocksServerReferrer {
    pub(crate) name: String,
    pub(crate) tcp_addr: SocketAddr,
}

#[derive(Debug)]
pub(crate) struct ReferredSocksServer {
    pub(crate) server: Arc<SocksServer>,
    pub(crate) stream: TcpStream,
}

impl SocksServerReferrer {
    pub(crate) fn new(tcp_addr: SocketAddr, name: Option<String>) -> Self {
        let name = name.unwrap_or_else(|| tcp_addr.to_string());
        Self { name, tcp_addr }
    }

    pub(crate) async fn negotiate(&self) -> io::Result<ReferredSocksServer> {
        let mut stream = TcpStream::connect(self.tcp_addr).await?;
        // Send request w/ auth method 0x00 (no auth)
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        // Server select auth method
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        match buf {
            // 0xff: no acceptable method
            [0x05, 0xff] => io_error!("Auth required by SOCKS server"),
            // 0x00：no auth required
            [0x05, 0x00] => (),
            _ => io_error!("Unrecognized reply from SOCKS server"),
        }
        // Send UDP associate request
        stream
            .write_all(&[
                // VER, CMD (UDP), RSV, ATYP (IPv4), DST.ADDR (0.0.0.0), DST.PORT (0)
                0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ])
            .await?;

        // Get UDP socket address from server's reply
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        match buf {
            // Success
            [0x05, 0x00] => (),
            [0x05, 0x07] => io_error!("SOCKS server do not support UDP associate"),
            [0x05, _] => io_error!("SOCKS server reject the request"),
            _ => io_error!("Unrecognized reply from SOCKS server"),
        }
        stream.read_u8().await?; // Reversed field
        let ip: IpAddr = match stream.read_u8().await? {
            // Address type
            ATYP_IPV4 => Ipv4Addr::from(stream.read_u32().await?).into(),
            ATYP_IPV6 => Ipv6Addr::from(stream.read_u128().await?).into(),
            _ => io_error!("Unsupported address type from SOCKS server"),
        };
        let port = stream.read_u16().await?;
        let udp_addr: SocketAddr = (ip, port).into();

        let server = SocksServer::new(udp_addr, Some(self.name.clone()));
        Ok(ReferredSocksServer {
            server: server.into(),
            stream,
        })
    }
}
