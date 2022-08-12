use std::{fmt, sync::Arc};

use bytes::Bytes;
use futures::{Sink, SinkExt, StreamExt};
use tracing::{info, trace, warn};

use crate::app::{
    socks5::SocksSession,
    types::{ClientAddr, RemoteAddr, UdpPackets},
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
            Some(name) => write!(f, "{})", name)?,
            None => write!(f, "{})", self.remote.0)?,
        }
        write!(f, ")")
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

    pub(crate) fn set_proxy<I>(&mut self, proxy: SocksSession, sender: I)
    where
        I: Sink<UdpPackets> + Send + Sync + 'static,
    {
        let proxy = Arc::new(proxy);
        let mut incoming = Box::pin(proxy.incoming());
        let mut sender = Box::pin(sender);
        self.proxy = Some(proxy);
        let client = self.client;
        let remote = self.remote;

        tokio::spawn(async move {
            trace!("Start forwarding {:?} => {:?}", remote, client);
            while let Some(result) = incoming.next().await {
                match result {
                    Err(err) => info!("Proxy read error: {}", err),
                    Ok(pkts) => {
                        trace!("{:?} => {:?}: {} packets", remote, client, pkts.len());
                        if sender.feed((client, remote, pkts)).await.is_err() {
                            warn!("TProxySender has been closed");
                            return;
                        }
                    }
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
