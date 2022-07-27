use std::{
    fmt::Debug,
    io::{self, ErrorKind},
};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use tracing::{debug, info, instrument, trace, warn};

use crate::app::{
    types::{ClientAddr, RemoteAddr},
    AppContext,
};

use super::bind::{BindSocks, Bindable};

pub(crate) struct SocksForwardService<S> {
    context: AppContext<S>,
}

impl<S: Default + Send + Sync + Debug> SocksForwardService<S> {
    pub(crate) fn new(context: AppContext<S>) -> Self {
        Self { context }
    }

    pub(crate) async fn serve<C, P>(&self, incoming_clients: C)
    where
        C: Stream<Item = (ClientAddr, P)>,
        P: Stream<Item = (RemoteAddr, Bytes)>,
    {
        incoming_clients
            .for_each_concurrent(None, |(client_addr, incoming_packets)| async move {
                debug!("New client from {:?}", client_addr);
                if let Err(err) = self.handle_client(client_addr, incoming_packets).await {
                    info!("Error on handle client {:?}: {}", client_addr, err);
                }
            })
            .await;
    }

    #[instrument(skip_all, fields(client=?client_addr))]
    async fn handle_client<P>(&self, client_addr: ClientAddr, incoming_packet: P) -> io::Result<()>
    where
        P: Stream<Item = (RemoteAddr, Bytes)>,
    {
        let proxy = self.select_proxy().await?;
        let proxy_cloned = proxy.clone();
        let proxy_ref = &proxy_cloned;
        let client_to_remote = incoming_packet.for_each(|(remote_addr, pkt)| async move {
            trace!(
                "{:?} => {:?}: {} bytes",
                client_addr,
                remote_addr,
                pkt.len()
            );
            if let Err(err) = proxy_ref.send_to(remote_addr, &pkt).await {
                info!(
                    "failed to forward {} bytes packet to remote {:?}: {}",
                    pkt.len(),
                    remote_addr,
                    err
                );
            }
        });
        let remote_to_client = proxy.for_each(|incoming| async move {
            match incoming {
                Err(err) => info!("Proxy read error: {}", err),
                Ok((remote_addr, pkt)) => {
                    trace!(
                        "{:?} => {:?}: {} bytes",
                        remote_addr,
                        client_addr,
                        pkt.len()
                    );
                }
            }
        });
        futures::future::join(client_to_remote, remote_to_client).await;
        Ok(())
    }

    async fn select_proxy(&self) -> io::Result<BindSocks<S>> {
        let proxy = self
            .context
            .socks5_servers()
            .first()
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "No avaiable proxy"))?
            .clone();
        proxy.bind().await
    }
}
