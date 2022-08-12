use std::io;

use futures::Sink;
use lru_time_cache::{Entry, LruCache};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tracing::{info, instrument, trace, warn};

use crate::app::{
    net::{AsyncUdpSocket, MsgArrayWriteBuffer},
    types::{RemoteAddr, UdpPackets},
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

    pub(crate) fn launch(mut self) -> impl Sink<UdpPackets> + Clone {
        let (sender, mut receiver) = mpsc::channel::<UdpPackets>(32);
        let mut buf = MsgArrayWriteBuffer::with_capacity(16);
        tokio::spawn(async move {
            while let Some((client, remote, pkts)) = receiver.recv().await {
                buf.clear();
                pkts.iter()
                    .for_each(|pkt| buf.push([pkt.clone()], Some(client.0)));
                if let Err(err) = self.send_packets(remote, &mut buf).await {
                    info!("Error on sending packet via tproxy: {}", err);
                }
            }
            warn!("TProxySender exited");
        });

        PollSender::new(sender)
    }

    #[instrument(skip_all, fields(src=?src))]
    async fn send_packets(
        &mut self,
        src: RemoteAddr,
        buf: &mut MsgArrayWriteBuffer<1>,
    ) -> io::Result<()> {
        let socket = match self.sockets.entry(src) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                trace!("Creating non-local socket");
                entry.insert(AsyncUdpSocket::bind_nonlocal(&src.0)?)
            }
        };
        while buf.has_remaining() {
            let (n, len) = socket.batch_send(buf).await?;
            buf.advance(n);
            trace!("Sent {} messages, {} bytes", n, len);
        }
        Ok(())
    }
}
