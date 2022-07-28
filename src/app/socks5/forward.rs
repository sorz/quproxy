use std::{
    fmt::Debug,
    io::{self, ErrorKind},
    sync::Arc,
};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt};
use lru_time_cache::{Entry, LruCache};
use tracing::{info, instrument, trace, warn};

use crate::app::{
    types::{ClientAddr, RemoteAddr, UdpPacket},
    AppContext,
};

use super::{
    bind::{BindSocks, Bindable},
    SocksServer,
};

pub(crate) struct SocksForwardService<S, I: Sink<UdpPacket>> {
    context: AppContext<S>,
    proxies: LruCache<ClientAddr, BindSocks<S>>,
    sender: I,
}

impl<
        S: Default + Send + Sync + Debug + 'static,
        I: Sink<UdpPacket> + Clone + Send + Sync + 'static,
    > SocksForwardService<S, I>
{
    pub(crate) fn new(context: AppContext<S>, sender: I) -> Self {
        Self {
            proxies: context.new_lru_cache_for_sessions(),
            context,
            sender,
        }
    }

    pub(crate) async fn serve<R>(mut self, receiver: R)
    where
        R: Stream<Item = UdpPacket>,
    {
        let mut receiver = Box::pin(receiver);
        while let Some((client, remote, pkt)) = receiver.next().await {
            if let Err(err) = self.send_packet(client, remote, pkt).await {
                info!("Error on sending packet to proxy: {}", err);
            }
        }
        warn!("SocksForwardService exited");
    }

    #[instrument(skip_all, fields(src=?src, dst=?dst, pkt_bytes=pkt.len()))]
    async fn send_packet(
        &mut self,
        src: ClientAddr,
        dst: RemoteAddr,
        pkt: Bytes,
    ) -> io::Result<()> {
        let proxy = self.select_proxy(src).await?;
        trace!(
            "{:?} => {:?} via {}: {} bytes",
            src,
            dst,
            pkt.len(),
            proxy.server.name
        );
        if let Err(err) = proxy.send_to(dst, &pkt).await {
            info!(
                "failed to forward {} bytes packet to remote {:?} via {}: {}",
                pkt.len(),
                dst,
                proxy.server.name,
                err
            );
        }
        Ok(())
    }

    async fn select_proxy(&mut self, client: ClientAddr) -> io::Result<&mut BindSocks<S>> {
        let socks = match self.proxies.entry(client) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let proxy = self
                    .context
                    .socks5_servers()
                    .first()
                    .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "No avaiable proxy"))?
                    .clone();
                let socks = new_proxy_session(proxy, client, self.sender.clone()).await?;
                entry.insert(socks)
            }
        };
        Ok(socks)
    }
}

async fn new_proxy_session<S, I>(
    proxy: Arc<SocksServer<S>>,
    client: ClientAddr,
    sender: I,
) -> io::Result<BindSocks<S>>
where
    S: Send + Sync + Debug + 'static,
    I: Sink<UdpPacket> + Send + Sync + 'static,
{
    let socks = proxy.bind().await?;
    let mut incoming = Box::pin(socks.incoming());
    let mut sender = Box::pin(sender);
    tokio::spawn(async move {
        while let Some(result) = incoming.next().await {
            match result {
                Err(err) => info!("Proxy read error: {}", err),
                Ok((remote, pkt)) => {
                    trace!("{:?} => {:?}: {} bytes", remote, client, pkt.len());
                    if sender.feed((client, remote, pkt)).await.is_err() {
                        warn!("TProxySender has been closed");
                        return;
                    }
                }
            }
        }
        trace!("UDP session for {:?} dropped", client);
    });
    Ok(socks)
}
