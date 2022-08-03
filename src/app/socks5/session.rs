use std::{
    fmt::{Display, Formatter},
    future::Future,
    io::{self, Result, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Weak,
    },
    task::{Context, Poll},
    time::Instant,
};

use async_trait::async_trait;
use byteorder::{ReadBytesExt, BE};
use bytes::Bytes;
use futures::{FutureExt, Stream};
use tokio::{io::ReadBuf, net::UdpSocket, sync::Notify};
use tracing::{debug, instrument, trace};

use crate::app::{
    socks5::Usage,
    status::Status,
    types::{ClientAddr, RemoteAddr},
};

use super::SocksServer;

const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;

#[async_trait]
pub(crate) trait Bindable<S: Status> {
    async fn bind(&self, client: Option<ClientAddr>) -> Result<Session<S>>;
    fn server_name(&self) -> &str;
}

#[async_trait]
impl<S: Status> Bindable<S> for Arc<SocksServer<S>> {
    async fn bind(&self, client: Option<ClientAddr>) -> Result<Session<S>> {
        let bind_ip: IpAddr = match self.udp_addr.ip() {
            IpAddr::V4(ip) if ip.is_loopback() => Ipv4Addr::LOCALHOST.into(),
            IpAddr::V6(ip) if ip.is_loopback() => Ipv6Addr::LOCALHOST.into(),
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        let socket = UdpSocket::bind((bind_ip, 0)).await?;
        socket.connect(self.udp_addr).await?;

        Ok(Session::new(self.clone(), socket, client))
    }

    fn server_name(&self) -> &str {
        &self.name
    }
}

pub(crate) struct Session<S: Status> {
    pub(crate) server: Arc<SocksServer<S>>,
    socket: UdpSocket,
    client: Option<ClientAddr>,
    pub(super) created_at: Instant,
    pub(super) tx_bytes: AtomicUsize,
    pub(super) rx_bytes: AtomicUsize,
    drop_notify: Arc<Notify>,
}

impl<S: Status> Display for Session<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.client {
            Some(ClientAddr(client)) => write!(f, "Session ({} <= {})", self.server.name, client),
            None => write!(f, "Session ({})", self.server.name),
        }
    }
}

impl<S: Status> Session<S> {
    fn new(server: Arc<SocksServer<S>>, socket: UdpSocket, client: Option<ClientAddr>) -> Self {
        AsRef::<Usage>::as_ref(&server.status).open_session();
        let session = Session {
            server,
            socket,
            client,
            drop_notify: Default::default(),
            created_at: Instant::now(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),
        };
        debug!("Open {}", session);
        session
    }

    #[instrument(skip_all, fields(buf_len=buf.len()))]
    pub(crate) async fn send_to_remote(&self, target: RemoteAddr, buf: &[u8]) -> Result<()> {
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
        let n = self.socket.send(&request).await?;
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
        AsRef::<Usage>::as_ref(&self.server.status).add_tx(n);
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

    pub(super) fn incoming(self: &Arc<Self>) -> SessionIncoming<S> {
        SessionIncoming::new(self)
    }
}

impl<S: Status> Drop for Session<S> {
    fn drop(&mut self) {
        let rx = *self.rx_bytes.get_mut();
        let tx = *self.tx_bytes.get_mut();
        AsRef::<Usage>::as_ref(&self.server.status).close_session();
        debug!(
            "Close {}, {:#?}, RX {}, TX {}",
            self,
            self.created_at.elapsed(),
            rx,
            tx
        );
        self.drop_notify.notify_waiters();
    }
}

pub(crate) struct SessionIncoming<S: Status> {
    session: Weak<Session<S>>,
    drop_notify: Pin<Box<dyn Future<Output = ()> + Sync + Send>>,
}

impl<S: Status> SessionIncoming<S> {
    fn new(session: &Arc<Session<S>>) -> Self {
        Self {
            session: Arc::downgrade(session),
            drop_notify: Box::pin(wait_notify(session.drop_notify.clone())),
        }
    }
}

async fn wait_notify(notify: Arc<Notify>) {
    notify.notified().await
}

impl<S: Status> Stream for SessionIncoming<S> {
    type Item = io::Result<(RemoteAddr, Bytes)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.drop_notify.poll_unpin(cx).is_ready() {
            // Socket dropped, return None to indicate the end of stream
            return Poll::Ready(None);
        }

        let session = match self.session.upgrade() {
            Some(session) => session,
            // Session dropped
            None => return Poll::Ready(None),
        };

        let mut buf_array = [0u8; 2048];
        let mut buf = ReadBuf::new(&mut buf_array);
        loop {
            match session.socket.poll_recv(cx, &mut buf) {
                Poll::Pending => break Poll::Pending,
                Poll::Ready(Err(err)) => break Poll::Ready(Some(Err(err))),
                Poll::Ready(Ok(())) => {
                    if let Some((pkt, remote)) = decode_packet(buf.filled()) {
                        session.rx_bytes.fetch_add(pkt.len(), Ordering::Relaxed);
                        AsRef::<Usage>::as_ref(&session.server.status).add_rx(pkt.len());
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
