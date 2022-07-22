use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{future, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::{interval_at, timeout, Instant};
use tracing::{debug, instrument, trace};

use crate::app::{
    socks5::{SocksConnect, SocksServer},
    AppContext,
};

#[derive(Debug)]
pub(crate) struct CheckingService {
    context: AppContext,
    check_interval: Duration,
    dns_addr: SocketAddr,
}

impl CheckingService {
    pub(crate) fn new(context: AppContext, check_interval: Duration, dns_addr: SocketAddr) -> Self {
        Self {
            context,
            check_interval,
            dns_addr,
        }
    }

    #[instrument(skip_all)]
    pub(crate) async fn launch(self) -> ! {
        let mut interval = interval_at(Instant::now(), self.check_interval);
        loop {
            interval.tick().await;
            self.check_all().await;
        }
    }

    #[instrument(skip_all)]
    async fn check_all(&self) {
        debug!("Start checking all servers");
        let max_wait = std::cmp::min(Duration::from_secs(4), self.check_interval);
        let checkings: FuturesUnordered<_> = self
            .context
            .socks5_servers()
            .into_iter()
            .map(|server| {
                println!("server: {:?}", server);
                Box::pin(async move {
                    let result = server.check_dns_query_delay(self.dns_addr, max_wait).await;
                    (server, result)
                })
            })
            .collect();
        checkings
            .for_each(|(server, result)| {
                println!("{}: {:?}ms", server.name, result);
                // TODO: update delay
                future::ready(())
            })
            .await;
        debug!("Finish checking all servers");
    }
}

#[async_trait]
trait Checkable: SocksConnect {
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
        let n = timeout(max_wait, async {
            let conn = self.connect(dns_addr).await?;
            trace!("Send DNS query: {:?}", query);
            conn.send_to(&query).await?;
            conn.recv(&mut buf).await
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
