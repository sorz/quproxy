use std::{
    io::{self, ErrorKind},
    sync::Arc,
};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt};
use lru_time_cache::{Entry, LruCache};
use tracing::{debug, info, trace, warn};

use crate::app::{
    status::Status,
    types::{ClientAddr, RemoteAddr, UdpPacket},
    AppContext,
};

use super::session::{Bindable, Session};

pub(crate) struct SocksForwardService<S: Status, I: Sink<UdpPacket>> {
    context: AppContext<S>,
    sessions: LruCache<ClientAddr, Arc<Session<S>>>,
    sender: I,
}

impl<S, I> SocksForwardService<S, I>
where
    S: Status,
    I: Sink<UdpPacket> + Clone + Send + Sync + 'static,
{
    pub(crate) fn new(context: &AppContext<S>, sender: I) -> Self {
        Self {
            context: context.clone(),
            sessions: context.new_lru_cache_for_sessions(),
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
            if let Err(err) = self.send_packet(client, remote, pkt).await {
                info!("Error on sending packet to proxy: {}", err);
            }
        }
        warn!("SOCKS forward service exited");
    }

    async fn send_packet(
        &mut self,
        src: ClientAddr,
        dst: RemoteAddr,
        pkt: Bytes,
    ) -> io::Result<()> {
        let session = self.retrive_session(src).await?;
        trace!(
            "{:?} => {:?} via {}: {} bytes",
            src,
            dst,
            pkt.len(),
            session.server.name
        );
        if let Err(err) = session.send_to_remote(dst, &pkt).await {
            info!(
                "failed to forward {} bytes packet to remote {:?} via {}: {}",
                pkt.len(),
                dst,
                session.server.name,
                err
            );
        }
        Ok(())
    }

    async fn retrive_session(&mut self, client: ClientAddr) -> io::Result<&Arc<Session<S>>> {
        let session = match self.sessions.entry(client) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // Select proxy & create new session
                let proxy = self
                    .context
                    .socks5_servers()
                    .first()
                    .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "No avaiable proxy"))?
                    .clone();
                let session: Arc<_> = proxy.bind(Some(client)).await?.into();
                let session_cloned = session.clone();
                let sender_cloned = self.sender.clone();
                tokio::spawn(async move {
                    session_cloned
                        .forward_remote_to_client(client, sender_cloned)
                        .await
                });
                entry.insert(session)
            }
        };
        Ok(session)
    }
}

impl<S: Status> Session<S> {
    async fn forward_remote_to_client<I>(self: Arc<Self>, client: ClientAddr, sender: I)
    where
        I: Sink<UdpPacket> + Send + Sync + 'static,
    {
        let mut incoming = Box::pin(self.incoming());
        let mut sender = Box::pin(sender);
        trace!("Start forwarding {} remote to client", self);
        drop(self); // no strong reference to the session
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
        trace!("Stop forwarding");
    }
}
