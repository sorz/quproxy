use async_trait::async_trait;
use byteorder::{ReadBytesExt, BE};
use std::{
    io::{Result, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::net::UdpSocket;
use tracing::{debug, instrument, trace};

use super::SocksServer;

const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;

#[async_trait]
pub(crate) trait SocksConnect {
    async fn connect(&self, target: SocketAddr) -> Result<SocksConnection>;
    fn server_name(&self) -> &str;
}

#[async_trait]
impl SocksConnect for Arc<SocksServer> {
    #[instrument]
    async fn connect(&self, target: SocketAddr) -> Result<SocksConnection> {
        let bind_ip: IpAddr = match self.udp_addr.ip() {
            IpAddr::V4(ip) if ip.is_loopback() => Ipv4Addr::LOCALHOST.into(),
            IpAddr::V6(ip) if ip.is_loopback() => Ipv6Addr::LOCALHOST.into(),
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        let socket = UdpSocket::bind((bind_ip, 0)).await?;
        socket.connect(self.udp_addr).await?;

        Ok(SocksConnection {
            server: self.clone(),
            socket,
            target,
        })
    }

    fn server_name(&self) -> &str {
        &self.name
    }
}

pub(crate) struct SocksConnection {
    server: Arc<SocksServer>,
    target: SocketAddr,
    socket: UdpSocket,
}

impl SocksConnection {
    #[instrument(skip_all, fields(buf_len=buf.len()))]
    pub(crate) async fn send_to(&self, buf: &[u8]) -> Result<()> {
        let mut request = Vec::with_capacity(buf.len() + 22);
        request.write_all(&[0x00, 0x00, 0x00])?;
        match self.target.ip() {
            IpAddr::V4(ip) => {
                request.write_all(&[ATYP_IPV4])?;
                request.write_all(&ip.octets())?;
            }
            IpAddr::V6(ip) => {
                request.write_all(&[ATYP_IPV6])?;
                request.write_all(&ip.octets())?;
            }
        }
        request.write_all(&self.target.port().to_be_bytes())?;
        request.write_all(buf)?;
        self.socket.send(&request).await?;
        Ok(())
    }

    #[instrument(skip_all, fields(server=self.server.name, target=?self.target))]
    pub(crate) async fn recv(&self, mut buf: &mut [u8]) -> Result<usize> {
        let mut req_buf = vec![0u8; 2048];
        loop {
            req_buf.resize(2048, 0);
            let n = self.socket.recv(&mut req_buf).await?;
            req_buf.resize(n, 0);
            trace!("Received {} bytes: {:?}", n, req_buf);
            if n < 10 {
                debug!("UDP request too short");
                continue;
            }
            let mut req = &req_buf[..];
            req.read_u16::<BE>()?; // reversed
            if req.read_u8()? != 0 {
                // fragment number
                debug!("Dropped UDP fragments");
                continue;
            }
            let target_ip: IpAddr = match req.read_u8()? {
                ATYP_IPV4 => Ipv4Addr::from(req.read_u32::<BE>()?).into(),
                ATYP_IPV6 => Ipv6Addr::from(req.read_u128::<BE>()?).into(),
                _ => {
                    debug!("Unsupported address type");
                    continue;
                }
            };
            let target: SocketAddr = (target_ip, req.read_u16::<BE>()?).into();
            trace!("Target: {}", target);
            if target != self.target {
                debug!("Target mismatched");
                continue;
            }
            return buf.write(req);
        }
    }
}
