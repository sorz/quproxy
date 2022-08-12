use std::{
    fmt::{Display, Formatter},
    future::Future,
    io::{self, Read, Result, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Instant,
};

use byteorder::{ReadBytesExt, WriteBytesExt, BE};
use bytes::{Buf, Bytes};
use futures::{FutureExt, Stream};
use tokio::{net::UdpSocket, sync::Notify};
use tracing::{debug, info, instrument};

use crate::app::net::{AsyncUdpSocket, MsgArrayReadBuffer, UDP_BATCH_SIZE, UDP_MAX_SIZE};

use super::{server::AppProto, traffic::AtomicTraffic, SocksServer};

const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;
const ATYP_NAME: u8 = 0x03;

#[derive(Debug)]
pub(crate) enum SocksTarget {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Name((String, u16)),
}

impl From<SocketAddr> for SocksTarget {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => SocksTarget::V4(addr),
            SocketAddr::V6(addr) => SocksTarget::V6(addr),
        }
    }
}

impl From<(String, u16)> for SocksTarget {
    fn from(value: (String, u16)) -> Self {
        SocksTarget::Name(value)
    }
}

impl Display for SocksTarget {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SocksTarget::V4(addr) => write!(f, "{}", addr),
            SocksTarget::V6(addr) => write!(f, "{}", addr),
            SocksTarget::Name((name, port)) => write!(f, "{}:{}", name, port),
        }
    }
}

impl SocksTarget {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            SocksTarget::V4(addr) => {
                writer.write_u8(ATYP_IPV4)?;
                writer.write_all(&addr.ip().octets())?;
                writer.write_u16::<BE>(addr.port())
            }
            SocksTarget::V6(addr) => {
                writer.write_u8(ATYP_IPV6)?;
                writer.write_all(&addr.ip().octets())?;
                writer.write_u16::<BE>(addr.port())
            }
            SocksTarget::Name((name, port)) => {
                writer.write_u8(ATYP_NAME)?;
                writer.write_u8(name.len().try_into().unwrap())?;
                writer.write_all(name.as_bytes())?;
                writer.write_u16::<BE>(*port)
            }
        }
    }

    pub(crate) fn proto(&self) -> AppProto {
        match self {
            SocksTarget::V4(_) => AppProto::IPv4,
            SocksTarget::V6(_) => AppProto::IPv6,
            SocksTarget::Name(_) => AppProto::Any,
        }
    }
}

impl SocksServer {
    pub(crate) async fn bind(self: &Arc<Self>, target: SocksTarget) -> Result<SocksSession> {
        let bind_ip: IpAddr = match self.udp_addr.ip() {
            IpAddr::V4(ip) if ip.is_loopback() => Ipv4Addr::LOCALHOST.into(),
            IpAddr::V6(ip) if ip.is_loopback() => Ipv6Addr::LOCALHOST.into(),
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        let socket = UdpSocket::bind((bind_ip, 0)).await?;
        socket.connect(self.udp_addr).await?;
        Ok(SocksSession::new(self.clone(), socket.try_into()?, target))
    }
}

pub(crate) struct SocksSession {
    pub(crate) server: Arc<SocksServer>,
    socket: AsyncUdpSocket,
    target: SocksTarget,
    pub(super) traffic: AtomicTraffic,
    created_at: Instant,
    drop_notify: Arc<Notify>,
}

impl Display for SocksSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SocksSession ({} => {})", self.server.name, self.target)
    }
}

impl SocksSession {
    fn new(server: Arc<SocksServer>, socket: AsyncUdpSocket, target: SocksTarget) -> Self {
        server.status.usage.open_session();
        let this = SocksSession {
            server,
            socket,
            target,
            created_at: Instant::now(),
            drop_notify: Default::default(),
            traffic: Default::default(),
        };
        debug!("Open {}", this);
        this
    }

    #[instrument(skip_all, fields(buf_len=buf.len()))]
    pub(crate) async fn send_to_remote(&self, buf: &[u8]) -> Result<()> {
        let mut request = Vec::with_capacity(buf.len() + 22);
        request.write_all(&[0x00, 0x00, 0x00])?;
        self.target.write_to(&mut request)?;
        request.write_all(buf)?;
        let n = self.socket.send(&request).await?;
        self.traffic.add_tx(n);
        self.server.status.usage.traffic.add_tx(n);
        Ok(())
    }

    pub(crate) fn incoming(self: &Arc<Self>) -> SessionIncoming {
        SessionIncoming::new(self)
    }
}

impl Drop for SocksSession {
    fn drop(&mut self) {
        self.drop_notify.notify_waiters();
        self.server.status.usage.close_session();
        debug!(
            "Close {}, {:#.0?}, {}",
            self,
            self.created_at.elapsed(),
            self.traffic.get(),
        );
    }
}

pub(crate) struct SessionIncoming {
    session: Weak<SocksSession>,
    drop_notify: Pin<Box<dyn Future<Output = ()> + Sync + Send>>,
    buf: Pin<Box<MsgArrayReadBuffer<UDP_BATCH_SIZE, UDP_MAX_SIZE>>>,
}

impl SessionIncoming {
    fn new(session: &Arc<SocksSession>) -> Self {
        Self {
            session: Arc::downgrade(session),
            drop_notify: Box::pin(wait_notify(session.drop_notify.clone())),
            buf: MsgArrayReadBuffer::new(),
        }
    }
}

async fn wait_notify(notify: Arc<Notify>) {
    notify.notified().await
}

impl Stream for SessionIncoming {
    type Item = io::Result<Box<[Bytes]>>;

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

        // Fill buffer
        self.buf.clear();
        match session.socket.poll_batch_recv(cx, &mut self.buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
            Poll::Ready(Ok(())) => {
                if self.buf.len() >= UDP_BATCH_SIZE / 2 {
                    // FIXME: remove it
                    info!(
                        "Upstream batch recv {}/{} messages",
                        self.buf.len(),
                        UDP_BATCH_SIZE
                    );
                }
            }
        }

        // Decode packets
        let pkts: Box<[_]> = self
            .buf
            .iter()
            .filter_map(|msg| match decode_packet(msg.buf) {
                Ok(buf) => {
                    session.traffic.add_rx(buf.len());
                    session.server.status.usage.traffic.add_rx(buf.len());
                    Some(Bytes::copy_from_slice(buf))
                }
                Err(err) => {
                    debug!("Failed to parse SOCKSv5 UDP: {}", { err });
                    None
                }
            })
            .collect();
        Poll::Ready(Some(Ok(pkts)))
    }
}

fn decode_packet(mut pkt: &[u8]) -> io::Result<&[u8]> {
    if pkt.len() < 10 {
        io_error!(UnexpectedEof, "UDP request too short");
    }
    pkt.read_u16::<BE>().unwrap(); // reversed
    if pkt.read_u8().unwrap() != 0 {
        // fragment number
        io_error!(InvalidData, "Fragmented UDP, dropped");
    }
    // Skip remote address
    match pkt.read_u8()? {
        ATYP_IPV4 => pkt.read_exact(&mut [0; 4])?,
        ATYP_IPV6 => pkt.read_exact(&mut [0; 16])?,
        ATYP_NAME => {
            let n = pkt.read_u8()?.into();
            if pkt.remaining() < n {
                io_error!(UnexpectedEof, "Truncated UDP request");
            }
            pkt.advance(n);
        }
        _ => io_error!(InvalidData, "Invalid address type, dropped"),
    }
    // Skip port number
    pkt.read_u16::<BE>()?;
    Ok(pkt)
}
