use async_trait::async_trait;
use byteorder::{ReadBytesExt, BE};
use bytes::Bytes;
use derivative::Derivative;
use futures::Stream;
use std::{
    fmt::Debug,
    io::{self, Result, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{io::ReadBuf, net::UdpSocket};
use tracing::{debug, instrument, trace};

use crate::app::types::RemoteAddr;

use super::SocksServer;

const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;

#[async_trait]
pub(crate) trait Bindable<S> {
    async fn bind(&self) -> Result<BindSocks<S>>;
    fn server_name(&self) -> &str;
}

#[async_trait]
impl<S: Send + Sync + Debug> Bindable<S> for Arc<SocksServer<S>> {
    #[instrument]
    async fn bind(&self) -> Result<BindSocks<S>> {
        let bind_ip: IpAddr = match self.udp_addr.ip() {
            IpAddr::V4(ip) if ip.is_loopback() => Ipv4Addr::LOCALHOST.into(),
            IpAddr::V6(ip) if ip.is_loopback() => Ipv6Addr::LOCALHOST.into(),
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        let socket = UdpSocket::bind((bind_ip, 0)).await?;
        socket.connect(self.udp_addr).await?;

        Ok(BindSocks {
            server: self.clone(),
            socket: socket.into(),
        })
    }

    fn server_name(&self) -> &str {
        &self.name
    }
}

#[derive(Derivative)]
#[derivative(Debug, Clone(bound = ""))]
pub(crate) struct BindSocks<S> {
    pub(crate) server: Arc<SocksServer<S>>,
    socket: Arc<UdpSocket>,
}

impl<S> BindSocks<S> {
    #[instrument(skip_all, fields(buf_len=buf.len()))]
    pub(crate) async fn send_to(&self, target: RemoteAddr, buf: &[u8]) -> Result<()> {
        let mut request = Vec::with_capacity(buf.len() + 22);
        request.write_all(&[0x00, 0x00, 0x00])?;
        match target.0.ip() {
            IpAddr::V4(ip) => {
                request.write_all(&[ATYP_IPV4])?;
                request.write_all(&ip.octets())?;
            }
            IpAddr::V6(ip) => {
                request.write_all(&[ATYP_IPV6])?;
                request.write_all(&ip.octets())?;
            }
        }
        request.write_all(&target.0.port().to_be_bytes())?;
        request.write_all(buf)?;
        self.socket.send(&request).await?;
        Ok(())
    }

    fn decode_packet<'a>(&self, mut pkt: &'a [u8]) -> Option<(&'a [u8], RemoteAddr)> {
        if pkt.len() < 10 {
            debug!("UDP request too short");
            return None;
        }
        pkt.read_u16::<BE>().unwrap(); // reversed
        if pkt.read_u8().unwrap() != 0 {
            // fragment number
            debug!("Dropped UDP fragments");
            return None;
        }
        let remote_ip: IpAddr = match pkt.read_u8().unwrap() {
            ATYP_IPV4 => Ipv4Addr::from(pkt.read_u32::<BE>().unwrap()).into(),
            ATYP_IPV6 => Ipv6Addr::from(pkt.read_u128::<BE>().unwrap()).into(),
            _ => {
                debug!("Unsupported address type");
                return None;
            }
        };
        let remote: SocketAddr = (remote_ip, pkt.read_u16::<BE>().unwrap()).into();
        trace!("Remote: {}", remote);
        Some((pkt, remote.into()))
    }

    #[instrument(skip_all, fields(server=self.server.name))]
    pub(crate) async fn recv_from(&self, mut buf: &mut [u8]) -> Result<(usize, RemoteAddr)> {
        let mut req_buf = vec![0u8; 2048];
        loop {
            req_buf.resize(2048, 0);
            let n = self.socket.recv(&mut req_buf).await?;
            req_buf.resize(n, 0);
            trace!("Received {} bytes: {:?}", n, req_buf);
            if let Some((pkt, remote)) = self.decode_packet(&req_buf) {
                let n = buf.write(pkt)?;
                return Ok((n, remote));
            }
        }
    }
}

impl<S> Stream for BindSocks<S> {
    type Item = io::Result<(RemoteAddr, Bytes)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut buf_array = [0u8; 2048];
        let mut buf = ReadBuf::new(&mut buf_array);
        loop {
            match self.socket.poll_recv(cx, &mut buf) {
                Poll::Pending => break Poll::Pending,
                Poll::Ready(Err(err)) => break Poll::Ready(Some(Err(err))),
                Poll::Ready(Ok(())) => {
                    if let Some((pkt, remote)) = self.decode_packet(buf.filled()) {
                        break Poll::Ready(Some(Ok((remote, Bytes::copy_from_slice(pkt)))));
                    }
                }
            }
            buf.clear()
        }
    }
}
