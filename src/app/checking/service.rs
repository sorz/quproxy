use async_trait::async_trait;
use derivative::Derivative;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    fmt::Debug,
    future, io,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};
use tokio::{
    select,
    time::{interval_at, timeout, Instant},
};
use tracing::{debug, info, instrument, trace};

use crate::app::{
    socks5::{Bindable, InnerProto, SocksServer},
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
            self.check_all().await;
        }
    }

    #[instrument(skip_all)]
    async fn check_all(&self) {
        trace!("Start checking all servers");
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
                        InnerProto::IPv4 => {
                            server.check_dns_query_delay(dns4.into(), max_wait).await
                        }
                        InnerProto::IPv6 | InnerProto::Inet => {
                            server.check_dns_query_delay(dns6.into(), max_wait).await
                        }
                        InnerProto::Unspecified => {
                            let result = select! {
                                r = server.check_dns_query_delay(dns4.into(), max_wait) => r,
                                r = server.check_dns_query_delay(dns6.into(), max_wait) => r,
                            };
                            if let Ok(rtt) = result {
                                let proto = server.probe_inner_proto(dns4, dns6, rtt).await;
                                server.inner_proto.set(proto);
                                info!("Set {}'s inner protocal to {:?}", server.name, proto);
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
                let mut health = server.status.health.lock();
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
        debug!("Check done, {}/{} up", ok, sum);
        let new_best_server = self.reorder_servers();
        if best_server != new_best_server {
            if let Some(server) = new_best_server {
                info!(
                    "Switch best server to {} {}",
                    server.name,
                    server.status.health.lock()
                )
            }
        }
    }

    fn reorder_servers(&self) -> Option<Arc<SocksServer>> {
        self.context.update_socks5_servers(|servers| {
            servers.sort_by_key(|h| {
                let health = h.status.health.lock();
                health.score()
            });
            servers.first().cloned()
        })
    }
}

#[async_trait]
trait Checkable: Bindable {
    #[instrument(skip_all, fields(server=self.server_name(), dns=?dns_addr))]
    async fn check_dns_query_delay(
        &self,
        dns_addr: SocketAddr,
        max_wait: Duration,
    ) -> io::Result<Duration> {
        trace!("Checking DNS query delay");
        // Construct DNS query for A record of "." (root)
        let query: [u8; 17] = [
            rand::random(),
            rand::random(), // transcation ID
            1,
            32, // standard query
            0,
            1, // one query
            0,
            0, // zero answer
            0,
            0, // zero authority
            0,
            0, // zero addition
            0, // query: root
            0,
            1, // query: type A
            0,
            1, // query: class IN
        ];
        let parse_tid = |req: &[u8]| (req[0] as u16) << 8 | (req[1] as u16);
        let query_tid = parse_tid(&query);

        // Send query & receive reply
        let t0 = Instant::now();
        let mut buf = [0u8; 12];
        let n = timeout(max_wait, async {
            let proxy = self.bind(None).await?;
            trace!("Send DNS query: {:?}", query);
            proxy.send_to_remote(dns_addr.into(), &query).await?;
            proxy.recv(&mut buf).await
        })
        .await??;

        // Validate reply
        if n < 12 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "DNS reply too short",
            ));
        }
        trace!("Recevied DNS reply (truncated): {:?}", &buf[..n]);
        if query_tid != parse_tid(&buf[..n]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "broken DNS reply received",
            ));
        }
        Ok(t0.elapsed())
    }

    #[instrument(skip_all, fields(server=self.server_name()))]
    async fn probe_inner_proto(
        &self,
        dns4: SocketAddrV4,
        dns6: SocketAddrV6,
        rtt: Duration,
    ) -> InnerProto {
        // False rate = p^N * (1-p)^N, where p is packet loss rate
        const N: usize = 3; // Max false rate (when p = 0.5) is 0.5^(3 * 2) = 1.6%
        let max_wait = rtt * 2;
        let mut v4_ok_cnt = 0usize;
        let mut v6_ok_cnt = 0usize;
        let mut test_cnt = 0usize;
        for _ in 0..N {
            test_cnt += 1;
            select! {
                Ok(_) = self.check_dns_query_delay(dns4.into(), max_wait) => v4_ok_cnt += 1,
                Ok(_) = self.check_dns_query_delay(dns6.into(), max_wait) => v6_ok_cnt += 1,
                else => (),
            }
            if v4_ok_cnt > 0 && v6_ok_cnt > 0 {
                break;
            }
        }
        debug!(
            "v4 {}/{}, v6 {}/{}",
            v4_ok_cnt, test_cnt, v6_ok_cnt, test_cnt
        );
        match (v4_ok_cnt, v6_ok_cnt) {
            (N, 0) => InnerProto::IPv4,
            (0, N) => InnerProto::IPv6,
            (0, 0) => InnerProto::Unspecified,
            (_, _) => InnerProto::Inet,
        }
    }
}

impl Checkable for Arc<SocksServer> {}
