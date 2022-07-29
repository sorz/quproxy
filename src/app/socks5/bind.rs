use std::{
    fmt::Debug,
    future::Future,
    io::{self, Result, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

use async_trait::async_trait;
use byteorder::{ReadBytesExt, BE};
use bytes::Bytes;
use derivative::Derivative;
use futures::{FutureExt, Stream};
use tokio::{io::ReadBuf, net::UdpSocket, sync::Notify};
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
            drop_notify: Default::default(),
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
    drop_notify: Arc<Notify>,
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

    #[instrument(skip_all, fields(server=self.server.name))]
    pub(crate) async fn recv_from(&self, mut buf: &mut [u8]) -> Result<(usize, RemoteAddr)> {
        let mut req_buf = vec![0u8; 2048];
        loop {
            req_buf.resize(2048, 0);
            let n = self.socket.recv(&mut req_buf).await?;
            req_buf.resize(n, 0);
            trace!("Received {} bytes: {:?}", n, req_buf);
            if let Some((pkt, remote)) = decode_packet(&req_buf) {
                let n = buf.write(pkt)?;
                return Ok((n, remote));
            }
        }
    }

    pub(super) fn incoming(&self) -> BindSocksIncoming {
        BindSocksIncoming::new(&self.socket, self.drop_notify.clone())
    }
}

impl<S> Drop for BindSocks<S> {
    fn drop(&mut self) {
        trace!("Drop SOCKS session {:?}", self.socket);
        self.drop_notify.notify_waiters();
    }
}

pub(crate) struct BindSocksIncoming {
    socket: Weak<UdpSocket>,
    drop_notify: Pin<Box<dyn Future<Output = ()> + Sync + Send>>,
}

impl BindSocksIncoming {
    fn new(socket: &Arc<UdpSocket>, notify: Arc<Notify>) -> Self {
        Self {
            socket: Arc::downgrade(socket),
            drop_notify: Box::pin(wait_notify(notify)),
        }
    }
}

async fn wait_notify(notify: Arc<Notify>) {
    notify.notified().await
}

impl Stream for BindSocksIncoming {
    type Item = io::Result<(RemoteAddr, Bytes)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.drop_notify.poll_unpin(cx).is_ready() {
            // Socket dropped, return None to indicate the end of stream
            return Poll::Ready(None);
        }

        let socket = match self.socket.upgrade() {
            Some(socket) => socket,
            // Socket dropped
            None => return Poll::Ready(None),
        };

        let mut buf_array = [0u8; 2048];
        let mut buf = ReadBuf::new(&mut buf_array);
        loop {
            match socket.poll_recv(cx, &mut buf) {
                Poll::Pending => break Poll::Pending,
                Poll::Ready(Err(err)) => break Poll::Ready(Some(Err(err))),
                Poll::Ready(Ok(())) => {
                    if let Some((pkt, remote)) = decode_packet(buf.filled()) {
                        break Poll::Ready(Some(Ok((remote, Bytes::copy_from_slice(pkt)))));
                    }
                }
            }
            buf.clear()
        }
    }
}

fn decode_packet(mut pkt: &[u8]) -> Option<(&[u8], RemoteAddr)> {
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
    Some((pkt, remote.into()))
}
