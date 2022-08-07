use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt};
use lru_time_cache::LruCache;
use tracing::{debug, info, trace, warn};

use crate::app::{
    socks5::quic::{self, QuicConnection},
    types::{ClientAddr, RemoteAddr, UdpPacket},
    AppContext,
};

use super::{
    server::AppProto,
    session::{Bindable, Session},
};

pub(crate) struct SocksForwardService<I: Sink<UdpPacket>> {
    context: AppContext,
    sessions: LruCache<ClientAddr, Arc<Session>>,
    sender: I,
}

impl<I> SocksForwardService<I>
where
    I: Sink<UdpPacket> + Clone + Send + Sync + 'static,
{
    pub(crate) fn new(context: &AppContext, sender: I) -> Self {
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
        if !self.sessions.contains_key(&client) {
            // Start new session
            let mut quic = None;
            if self.context.cli_args.remote_dns && pkt.len() >= quic::MIN_DATAGRAM_SIZE_BYTES {
                if let Ok(init_pkt) = quic::InitialPacket::decode(pkt.clone()) {
                    trace!("QUIC Initial packet decoded");
                    if let Ok(conn) = QuicConnection::try_from(remote, init_pkt) {
                        trace!("Decoded: {:?}", quic);
                        quic = Some(conn);
                    }
                }
            }
            let session: Arc<Session> = self.create_session(client, remote, quic).await?.into();
            self.start_session(session.clone(), client);
            self.sessions.insert(client, session);
        }
        let session = self.sessions.get(&client).expect("unreachable");
        trace!(
            "{:?} => {:?} via {}: {} bytes",
            client,
            remote,
            pkt.len(),
            session.server.name
        );
        if let Err(err) = session.send_to_remote(remote, &pkt).await {
            info!(
                "failed to forward {} bytes packet to remote {:?} via {}: {}",
                pkt.len(),
                remote,
                session.server.name,
                err
            );
        }
        Ok(())
    }

    async fn create_session(
        &self,
        client: ClientAddr,
        remote: RemoteAddr,
        quic: Option<QuicConnection>,
    ) -> io::Result<Session> {
        let proto = match (remote, &quic) {
            (_, Some(quic)) if quic.remote_name.is_some() => AppProto::Any,
            (RemoteAddr(SocketAddr::V4(_)), _) => AppProto::IPv4,
            (RemoteAddr(SocketAddr::V6(_)), _) => AppProto::IPv6,
        };
        let proxy = self
            .context
            .socks5_servers()
            .into_iter()
            .find(|p| p.inner_proto.get().capable(proto))
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "No avaiable proxy"))?
            .clone();
        let mut session = proxy.bind(Some(client)).await?;
        if let Some(quic) = quic {
            session.set_quic(quic);
        }
        Ok(session)
    }

    fn start_session(&self, session: Arc<Session>, client: ClientAddr) {
        debug!("Open {}", session);
        let sender = self.sender.clone();
        tokio::spawn(async move { session.forward_remote_to_client(client, sender).await });
    }
}

impl Session {
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
