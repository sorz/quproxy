use derivative::Derivative;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{fmt::Debug, future, sync::Arc, time::Duration};
use tokio::time::{interval_at, Instant};
use tracing::{debug, info, instrument, trace};

use crate::app::{
    checking::{ping::Pingable, Healthy, PING_MAX_RETRY},
    socks5::{InnerProto, SocksServer},
    AppContext,
};

use super::meter::Sampling;

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
        let mut interval_ping = interval_at(Instant::now(), self.context.cli_args.check_interval);
        let mut interval_meter = interval_at(Instant::now(), Duration::from_secs(1));
        let task_ping = async {
            loop {
                interval_ping.tick().await;
                self.ping_all().await;
            }
        };
        let task_meter = async {
            loop {
                interval_meter.tick().await;
                self.meter_sampling_all().await;
            }
        };
        tokio::join!(task_ping, task_meter).0
    }

    #[instrument(skip_all)]
    async fn ping_all(&self) {
        trace!("Ping all servers");
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
                        InnerProto::IPv4 => {
                            server
                                .ping_with_dns_query(dns4.into(), PING_MAX_RETRY)
                                .await
                        }
                        InnerProto::IPv6 | InnerProto::Inet => {
                            server
                                .ping_with_dns_query(dns6.into(), PING_MAX_RETRY)
                                .await
                        }
                        InnerProto::Unspecified => {
                            let result = tokio::select! {
                                r = server.ping_with_dns_query(dns4.into(), PING_MAX_RETRY) => r,
                                r = server.ping_with_dns_query(dns6.into(), PING_MAX_RETRY) => r,
                            };
                            if matches!(result, Ok(Some(_))) {
                                let proto = server.probe_inner_proto(dns4, dns6).await;
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
            .inspect(|(server, result)| match result {
                Err(err) => {
                    info!("Failed to ping upstream [{}]: {}", server.name, err);
                    server.set_troubleness(true);
                }
                Ok(None) => {
                    debug!("Upstream [{}] is unreachable", server.name);
                    server.set_troubleness(true);
                }
                Ok(Some(_)) => (),
            })
            .fold((0usize, 0usize), |(sum, ok), (_, result)| {
                future::ready((
                    sum + 1,
                    ok + if result.ok().flatten().is_some() {
                        1
                    } else {
                        0
                    },
                ))
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

    #[instrument(skip_all)]
    async fn meter_sampling_all(&self) {
        self.context.socks5_servers().into_iter().for_each(|proxy| {
            if proxy.sample_traffic() && proxy.is_healthy() {
                // Upstream maybe in trouble
                let ctx = self.context.clone();
                // FIXME: avoid duplicated spawn
                tokio::spawn(async move {
                    proxy.check_troubleness(&ctx).await;
                });
            }
        });
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
