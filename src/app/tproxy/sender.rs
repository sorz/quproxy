use std::io;

use bytes::Bytes;
use futures::Sink;
use lru_time_cache::{Entry, LruCache};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tracing::{info, instrument, trace, warn};

use crate::app::{
    net::AsyncUdpSocket,
    types::{ClientAddr, RemoteAddr, UdpPacket},
    AppContext,
};

pub(crate) struct TProxySender {
    _context: AppContext,
    sockets: LruCache<RemoteAddr, AsyncUdpSocket>,
}

impl TProxySender {
    pub(crate) fn new(context: &AppContext) -> Self {
        Self {
            _context: context.clone(),
            sockets: context.new_lru_cache_for_sessions(),
        }
    }

    pub(crate) fn launch(mut self) -> impl Sink<UdpPacket> + Clone {
        let (sender, mut receiver) = mpsc::channel(32);
        tokio::spawn(async move {
            while let Some((client, remote, pkt)) = receiver.recv().await {
                if let Err(err) = self.send_packet(remote, client, pkt).await {
                    info!("Error on sending packet via tproxy: {}", err);
                }
            }
            warn!("TProxySender exited");
        });

        PollSender::new(sender)
    }

    #[instrument(skip_all, fields(src=?src, dst=?dst, pkt_bytes=pkt.len()))]
    async fn send_packet(
        &mut self,
        src: RemoteAddr,
        dst: ClientAddr,
        pkt: Bytes,
    ) -> io::Result<()> {
        let socket = match self.sockets.entry(src) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                trace!("Creating non-local socket");
                entry.insert(AsyncUdpSocket::bind_nonlocal(&src.0)?)
            }
        };
        socket.send_to(&pkt, dst.0).await?;
        Ok(())
    }
}
