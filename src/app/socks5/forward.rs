use std::io::{self, ErrorKind};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use lru_time_cache::LruCache;
use tracing::{debug, info, trace, warn};

use crate::app::{
    checking::Healthy,
    net::{MsgArrayWriteBuffer, UDP_BATCH_SIZE},
    quic::QuicConn,
    quic::MIN_INITIAL_PACKET_SIZE_BYTES,
    tproxy::TProxySenderCache,
    types::{ClientAddr, RemoteAddr, UdpPackets},
    AppContext,
};

use super::{session::SocksSession, SocksTarget};

pub(crate) struct SocksForwardService {
    context: AppContext,
    conns: LruCache<(ClientAddr, RemoteAddr), QuicConn>,
    senders: TProxySenderCache,
    buf: MsgArrayWriteBuffer<2>,
}

impl SocksForwardService {
    pub(crate) fn new(context: &AppContext) -> Self {
        Self {
            context: context.clone(),
            conns: context.new_lru_cache_for_sessions(),
            senders: TProxySenderCache::new(),
            buf: MsgArrayWriteBuffer::with_capacity(UDP_BATCH_SIZE),
        }
    }

    pub(crate) async fn serve<R>(mut self, receiver: R)
    where
        R: Stream<Item = UdpPackets>,
    {
        debug!("SOCKS forward service started");
        let mut receiver = Box::pin(receiver);
        while let Some((client, remote, pkts)) = receiver.next().await {
            if pkts.is_empty() {
                warn!("Empty list of packets");
                continue;
            }
            if let Err(err) = self.forward_client_to_remote(client, remote, &pkts).await {
                info!("Error on sending packet to proxy: {}", err);
            }
        }
        warn!("SOCKS forward service exited");
    }

    async fn forward_client_to_remote(
        &mut self,
        client: ClientAddr,
        remote: RemoteAddr,
        pkts: &[Bytes],
    ) -> io::Result<()> {
        let key = &(client, remote);
        let conn = if !self.conns.contains_key(key) {
            // Start new QUIC conn
            let conn = if self.context.cli_args.remote_dns
                && pkts[0].len() >= MIN_INITIAL_PACKET_SIZE_BYTES
            {
                QuicConn::new(remote, client, Some(pkts[0].clone()))
            } else {
                QuicConn::new(remote, client, None)
            };
            debug!("Open {}", conn);
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
            conn.set_proxy(proxy, self.senders.get_or_create(remote)?);
        }
        // Forward packet
        if let Some(proxy) = conn.proxy() {
            trace!(
                "{:?} => {:?} via {}: {} packets",
                client,
                remote,
                proxy.server.name,
                pkts.len(),
            );
            if let Err(err) = proxy.send_to_remote(pkts, &mut self.buf).await {
                proxy.server.set_troubleness(true);
                // TODO: retry with new upstream?
                info!(
                    "failed to forward {} packets to remote {:?} via {}: {}",
                    pkts.len(),
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
