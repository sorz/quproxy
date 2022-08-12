use std::io::{self, ErrorKind};

use bytes::Bytes;
use futures::{Sink, Stream, StreamExt};
use lru_time_cache::LruCache;
use tracing::{debug, info, trace, warn};

use crate::app::{
    checking::Healthy,
    quic::QuicConn,
    quic::MIN_INITIAL_PACKET_SIZE_BYTES,
    types::{ClientAddr, RemoteAddr, UdpPacket, UdpPackets},
    AppContext,
};

use super::{session::SocksSession, SocksTarget};

pub(crate) struct SocksForwardService<I: Sink<UdpPackets>> {
    context: AppContext,
    conns: LruCache<(ClientAddr, RemoteAddr), QuicConn>,
    sender: I,
}

impl<I> SocksForwardService<I>
where
    I: Sink<UdpPackets> + Clone + Send + Sync + 'static,
{
    pub(crate) fn new(context: &AppContext, sender: I) -> Self {
        Self {
            context: context.clone(),
            conns: context.new_lru_cache_for_sessions(),
            sender,
        }
    }

    pub(crate) async fn serve<R>(mut self, receiver: R)
    where
        R: Stream<Item = UdpPacket>,
    {
        debug!("SOCKS forward service started");
        let mut receiver = Box::pin(receiver);
        while let Some((client, remote, pkt)) = receiver.next().await {
            if let Err(err) = self.forward_client_to_remote(client, remote, pkt).await {
                info!("Error on sending packet to proxy: {}", err);
            }
        }
        warn!("SOCKS forward service exited");
    }

    async fn forward_client_to_remote(
        &mut self,
        client: ClientAddr,
        remote: RemoteAddr,
        pkt: Bytes,
    ) -> io::Result<()> {
        let key = &(client, remote);
        let conn = if !self.conns.contains_key(key) {
            // Start new QUIC conn
            let conn =
                if self.context.cli_args.remote_dns && pkt.len() >= MIN_INITIAL_PACKET_SIZE_BYTES {
                    QuicConn::new(remote, client, Some(pkt.clone()))
                } else {
                    QuicConn::new(remote, client, None)
                };
            self.conns.entry(*key).or_insert(conn)
        } else {
            self.conns.get_mut(key).unwrap()
        };
        // Check if to do migration
        if let Some(proxy) = conn.proxy() {
            if !proxy.server.is_healthy() {
                debug!("Migrating {:?} away from [{}]", client, proxy.server.name);
                conn.clear_proxy();
            }
        }
        // Connect to proxy
        if conn.proxy().is_none() {
            let target = if let Some(name) = &conn.remote_name {
                (name.clone(), conn.remote.0.port()).into()
            } else {
                conn.remote.0.into()
            };
            let proxy = select_proxy(&self.context, target).await?;
            conn.set_proxy(proxy, self.sender.clone());
        }
        // Forward packet
        if let Some(proxy) = conn.proxy() {
            trace!(
                "{:?} => {:?} via {}: {} bytes",
                client,
                remote,
                proxy.server.name,
                pkt.len(),
            );
            if let Err(err) = proxy.send_to_remote(&pkt).await {
                proxy.server.set_troubleness(true);
                // TODO: retry with new upstream?
                info!(
                    "failed to forward {} bytes packet to remote {:?} via {}: {}",
                    pkt.len(),
                    remote,
                    proxy.server.name,
                    err
                );
            }
        }
        Ok(())
    }
}

async fn select_proxy(context: &AppContext, target: SocksTarget) -> io::Result<SocksSession> {
    let proto = target.proto();
    let proxy = context
        .socks5_servers()
        .into_iter()
        .find(|p| p.inner_proto.get().capable(proto) && p.is_healthy())
        .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "No avaiable proxy"))?
        .clone();
    proxy.bind(target).await
}
