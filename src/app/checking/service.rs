use async_trait::async_trait;
use derivative::Derivative;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{fmt::Debug, future, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::{interval_at, timeout, Instant};
use tracing::{debug, instrument, trace};

use crate::app::{
    socks5::{Bindable, SocksServer},
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
        let dns_addr = self.context.cli_args.check_dns_server;
        let checkings: FuturesUnordered<_> = self
            .context
            .socks5_servers()
            .into_iter()
            .map(|server| {
                Box::pin(async move {
                    let result = server.check_dns_query_delay(dns_addr, max_wait).await;
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
        debug!("Checking DNS query delay");
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
        let (n, _) = timeout(max_wait, async {
            let proxy = self.bind(None).await?;
            trace!("Send DNS query: {:?}", query);
            proxy.send_to_remote(dns_addr.into(), &query).await?;
            proxy.recv_from(&mut buf).await
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
}

impl Checkable for Arc<SocksServer> {}
