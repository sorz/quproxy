use std::{
    fmt::{Display, Formatter},
    future::Future,
    io::{self, ErrorKind, Read, Result, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Instant,
};

use byteorder::{ReadBytesExt, WriteBytesExt, BE};
use bytes::Bytes;
use futures::{FutureExt, Stream};
use tokio::{io::ReadBuf, net::UdpSocket, sync::Notify};
use tracing::{debug, instrument, trace};

use crate::app::types::{ClientAddr, RemoteAddr};

use super::{quic::QuicConnection, traffic::AtomicTraffic, SocksServer};

const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;
const ATYP_NAME: u8 = 0x03;

enum SocksDstAddr<T> {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Name(T),
}

impl<T> From<IpAddr> for SocksDstAddr<T> {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => SocksDstAddr::Ipv4(addr),
            IpAddr::V6(addr) => SocksDstAddr::Ipv6(addr),
        }
    }
}

impl<T: AsRef<str>> SocksDstAddr<T> {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            SocksDstAddr::Ipv4(addr) => {
                writer.write_u8(ATYP_IPV4)?;
                writer.write_all(&addr.octets())
            }
            SocksDstAddr::Ipv6(addr) => {
                writer.write_u8(ATYP_IPV6)?;
                writer.write_all(&addr.octets())
            }
            SocksDstAddr::Name(name) => {
                writer.write_u8(ATYP_NAME)?;
                writer.write_u8(name.as_ref().len().try_into().unwrap())?;
                writer.write_all(name.as_ref().as_bytes())
            }
        }
    }
}

impl SocksDstAddr<String> {
    fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let addr = match reader.read_u8()? {
            ATYP_IPV4 => SocksDstAddr::Ipv4(Ipv4Addr::from(reader.read_u32::<BE>()?)),
            ATYP_IPV6 => SocksDstAddr::Ipv6(Ipv6Addr::from(reader.read_u128::<BE>()?)),
            ATYP_NAME => {
                let len = reader.read_u8()? as usize;
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf)?;
                let name = String::from_utf8(buf)
                    .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;
                SocksDstAddr::Name(name)
            }
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Unsupported address type",
                ))
            }
        };
        Ok(addr)
    }
}

impl SocksServer {
    pub(crate) async fn bind(self: &Arc<Self>, client: Option<ClientAddr>) -> Result<Session> {
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
}

pub(crate) struct Session {
    pub(crate) server: Arc<SocksServer>,
    socket: UdpSocket,
    client: Option<ClientAddr>,
    pub(super) quic: Option<QuicConnection>,
    pub(super) created_at: Instant,
    pub(super) traffic: AtomicTraffic,
    drop_notify: Arc<Notify>,
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.client {
            Some(ClientAddr(client)) => {
                write!(f, "Session ({} => {}", client.ip(), self.server.name)?
            }
            None => write!(f, "Session ({}", self.server.name)?,
        }
        if let Some(QuicConnection {
            remote_name: Some(name),
            ..
        }) = &self.quic
        {
            write!(f, " => {}", name)?;
        }
        write!(f, ")")
    }
}

impl Session {
    fn new(server: Arc<SocksServer>, socket: UdpSocket, client: Option<ClientAddr>) -> Self {
        server.status.usage.open_session();
        Session {
            server,
            socket,
            client,
            quic: None,
            drop_notify: Default::default(),
            created_at: Instant::now(),
            traffic: Default::default(),
        }
    }

    #[instrument(skip_all, fields(buf_len=buf.len()))]
    pub(crate) async fn send_to_remote(&self, target: RemoteAddr, buf: &[u8]) -> Result<()> {
        let mut request = Vec::with_capacity(buf.len() + 22);
        request.write_all(&[0x00, 0x00, 0x00])?;
        let addr = match &self.quic {
            Some(QuicConnection {
                remote_orig,
                remote_name: Some(remote_name),
            }) if remote_orig == &target => {
                // Remote DNS resolve enabled
                SocksDstAddr::Name(remote_name)
            }
            _ => target.0.ip().into(),
        };
        addr.write_to(&mut request)?;
        request.write_all(&target.0.port().to_be_bytes())?;
        request.write_all(buf)?;
        let n = self.socket.send(&request).await?;
        self.traffic.add_tx(n);
        self.server.status.usage.traffic.add_tx(n);
        Ok(())
    }

    #[instrument(skip_all, fields(server=self.server.name))]
    pub(crate) async fn recv(&self, mut buf: &mut [u8]) -> Result<usize> {
        let mut req_buf = vec![0u8; 2048];
        loop {
            req_buf.resize(2048, 0);
            let n = self.socket.recv(&mut req_buf).await?;
            req_buf.resize(n, 0);
            trace!("Received {} bytes: {:?}", n, req_buf);
            if let Some((pkt, _, _)) = decode_packet(&req_buf) {
                let n = buf.write(pkt)?;
                return Ok(n);
            }
        }
    }

    pub(super) fn incoming(self: &Arc<Self>) -> SessionIncoming {
        SessionIncoming::new(self)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.server.status.usage.close_session();
        debug!(
            "Close {}, {:#.0?}, {}",
            self,
            self.created_at.elapsed(),
            self.traffic.get(),
        );
        self.drop_notify.notify_waiters();
    }
}

pub(crate) struct SessionIncoming {
    session: Weak<Session>,
    override_remote: Option<RemoteAddr>,
    drop_notify: Pin<Box<dyn Future<Output = ()> + Sync + Send>>,
}

impl SessionIncoming {
    fn new(session: &Arc<Session>) -> Self {
        let override_remote = if let Some(QuicConnection {
            remote_name: Some(_),
            remote_orig,
        }) = session.quic
        {
            Some(remote_orig)
        } else {
            None
        };
        Self {
            session: Arc::downgrade(session),
            override_remote,
            drop_notify: Box::pin(wait_notify(session.drop_notify.clone())),
        }
    }
}

async fn wait_notify(notify: Arc<Notify>) {
    notify.notified().await
}

macro_rules! ready_io_err {
    ($kind:ident, $err:expr) => {
        Poll::Ready(Some(Err(io::Error::new(ErrorKind::$kind, $err))))
    };
}

impl Stream for SessionIncoming {
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
                    if let Some((pkt, addr, port)) = decode_packet(buf.filled()) {
                        session.traffic.add_rx(pkt.len());
                        session.server.status.usage.traffic.add_rx(pkt.len());
                        let remote: RemoteAddr = if let Some(remote) = self.override_remote {
                            remote
                        } else {
                            match addr {
                                SocksDstAddr::Ipv4(ip) => SocketAddr::from((ip, port)).into(),
                                SocksDstAddr::Ipv6(ip) => SocketAddr::from((ip, port)).into(),
                                SocksDstAddr::Name(name) => {
                                    break ready_io_err!(
                                        InvalidData,
                                        format!(
                                            "Unexpected domain name `{}`, remote DNS not in use",
                                            name
                                        )
                                    )
                                }
                            }
                        };
                        break Poll::Ready(Some(Ok((remote, Bytes::copy_from_slice(pkt)))));
                    }
                }
            }
            buf.clear()
        }
    }
}

fn decode_packet(mut pkt: &[u8]) -> Option<(&[u8], SocksDstAddr<String>, u16)> {
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
    let remote = match SocksDstAddr::read_from(&mut pkt) {
        Ok(addr) => addr,
        Err(err) => {
            debug!("{}", err);
            return None;
        }
    };
    let port = pkt.read_u16::<BE>().unwrap();
    Some((pkt, remote, port))
}
