use std::io;

use bytes::Bytes;
use futures::Sink;
use lru_time_cache::{Entry, LruCache};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tracing::{info, instrument, trace, warn};

use crate::app::{
    types::{ClientAddr, RemoteAddr, UdpPacket},
    AppContext,
};

use super::socket::AsyncUdpSocket;

pub(crate) struct TProxySender<S> {
    context: AppContext<S>,
    sockets: LruCache<RemoteAddr, AsyncUdpSocket>,
}

impl<S: Send + Sync + 'static> TProxySender<S> {
    pub(crate) fn new(context: AppContext<S>) -> Self {
        Self {
            sockets: context.new_lru_cache_for_sessions(),
            context,
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
        socket.send_to(&pkt, dst).await?;
        Ok(())
    }
}
