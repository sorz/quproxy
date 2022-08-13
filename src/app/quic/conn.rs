use std::{fmt, io, sync::Arc};

use bytes::Bytes;
use futures::StreamExt;
use tracing::{info, trace};

use crate::app::{
    net::{MsgArrayWriteBuffer, UDP_BATCH_SIZE},
    socks5::SocksSession,
    tproxy::TProxySender,
    types::{ClientAddr, RemoteAddr},
};

use super::packet;

pub(crate) struct QuicConn {
    pub(crate) remote: RemoteAddr,
    pub(crate) remote_name: Option<String>,
    pub(crate) client: ClientAddr,
    proxy: Option<Arc<SocksSession>>,
}

impl fmt::Display for QuicConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QuicConn ({} => ", self.client.0)?;
        if let Some(proxy) = &self.proxy {
            write!(f, "{} => ", proxy.server.name)?;
        }
        match &self.remote_name {
            Some(name) => write!(f, "{}/{})", name, self.remote.0),
            None => write!(f, "{})", self.remote.0),
        }
    }
}

impl QuicConn {
    pub(crate) fn new(remote: RemoteAddr, client: ClientAddr, pkt: Option<Bytes>) -> Self {
        Self {
            remote,
            client,
            remote_name: pkt.and_then(packet::get_server_name),
            proxy: None,
        }
    }

    pub(crate) fn set_proxy(&mut self, proxy: SocksSession, sender: Arc<TProxySender>) {
        let proxy = Arc::new(proxy);
        let mut incoming = Box::pin(proxy.incoming());
        self.proxy = Some(proxy);
        let client = self.client;
        let remote = self.remote;

        tokio::spawn(async move {
            trace!("Start forwarding {:?} => {:?}", remote, client);
            let mut buf = MsgArrayWriteBuffer::<1>::with_capacity(UDP_BATCH_SIZE / 2);
            while let Some(pkts) = incoming.next().await {
                match forward_packets(pkts, client, &sender, &mut buf).await {
                    Err(err) => info!("Forwarding to client error: {}", err),
                    Ok((n, len)) => trace!("{:?} => {:?}: {} pkts {}B", remote, client, n, len),
                }
            }
            trace!("Stop forwarding");
        });
    }

    pub(crate) fn clear_proxy(&mut self) {
        self.proxy.take();
    }

    pub(crate) fn proxy(&self) -> Option<&SocksSession> {
        self.proxy.as_ref().map(|p| p.as_ref())
    }
}

impl Drop for QuicConn {
    fn drop(&mut self) {
        trace!("Close {}", self);
    }
}

async fn forward_packets(
    pkts: io::Result<Box<[Bytes]>>,
    client: ClientAddr,
    sender: &TProxySender,
    buf: &mut MsgArrayWriteBuffer<1>,
) -> io::Result<(usize, usize)> {
    buf.clear();
    pkts?
        .iter()
        .for_each(|pkt| buf.push([pkt.clone()], Some(client.0)));
    let mut total_n = 0;
    let mut total_len = 0;
    while buf.has_remaining() {
        let (n, len) = sender.as_ref().batch_send(buf).await?;
        buf.advance(n);
        total_n += n;
        total_len += len;
    }
    Ok((total_n, total_len))
}
