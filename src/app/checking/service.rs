use derivative::Derivative;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{fmt::Debug, future, sync::Arc, time::Duration};
use tokio::time::{interval_at, Instant};
use tracing::{debug, info, instrument, trace};

use crate::app::{
    checking::ping::Pingable,
    socks5::{InnerProto, SocksServer},
    AppContext,
};

#[derive(Derivative, Debug)]
pub(crate) struct CheckingService {
    #[derivative(Debug = "ignore")]
    context: AppContext,
}

impl CheckingService {
    pub(crate) fn new(context: &AppContext) -> Self {
        Self {
            context: context.clone(),
        }
    }

    #[instrument(skip_all)]
    pub(crate) async fn launch(self) -> ! {
        debug!("Checking service started");
        let mut interval = interval_at(Instant::now(), self.context.cli_args.check_interval);
        loop {
            interval.tick().await;
            self.ping_all().await;
        }
    }

    #[instrument(skip_all)]
    async fn ping_all(&self) {
        trace!("Ping all servers");
        let max_wait = std::cmp::min(Duration::from_secs(4), self.context.cli_args.check_interval);
        let dns4 = self.context.cli_args.check_dns_server_v4;
        let dns6 = self.context.cli_args.check_dns_server_v6;
        let servers = self.context.socks5_servers();
        let best_server = servers.first().cloned();
        let checkings: FuturesUnordered<_> = self
            .context
            .socks5_servers()
            .into_iter()
            .map(|server| {
                Box::pin(async move {
                    let result = match server.inner_proto.get() {
                        InnerProto::IPv4 => server.ping_with_dns_query(dns4.into(), max_wait).await,
                        InnerProto::IPv6 | InnerProto::Inet => {
                            server.ping_with_dns_query(dns6.into(), max_wait).await
                        }
                        InnerProto::Unspecified => {
                            let result = tokio::select! {
                                r = server.ping_with_dns_query(dns4.into(), max_wait) => r,
                                r = server.ping_with_dns_query(dns6.into(), max_wait) => r,
                            };
                            if let Ok(rtt) = result {
                                let proto = server.probe_inner_proto(dns4, dns6, rtt).await;
                                server.inner_proto.set(proto);
                                info!("Set [{}] inner protocal: {:?}", server.name, proto);
                            }
                            result
                        }
                    };
                    (server, result)
                })
            })
            .collect();
        let (sum, ok) = checkings
            .inspect(|(server, result)| {
                let delay = result.as_ref().ok().map(|t| (*t).into());
                let mut health = server.status.pings.lock();
                health.add_measurement(delay);
                trace!(
                    "{}: avg delay {:?}, {}% loss",
                    server.name,
                    health.average_delay(),
                    health.loss_percent()
                );
            })
            .fold((0usize, 0usize), |(sum, ok), (_, result)| {
                future::ready((sum + 1, ok + if result.is_ok() { 1 } else { 0 }))
            })
            .await;
        debug!("All pinged, {}/{} up", ok, sum);
        let new_best_server = self.resort_servers();
        if best_server != new_best_server {
            if let Some(server) = new_best_server {
                info!(
                    "Switch best server to {} {}",
                    server.name,
                    server.status.pings.lock()
                )
            }
        }
    }

    fn resort_servers(&self) -> Option<Arc<SocksServer>> {
        self.context.update_socks5_servers(|servers| {
            servers.sort_by_key(|h| {
                let health = h.status.pings.lock();
                health.score()
            });
            servers.first().cloned()
        })
    }
}
