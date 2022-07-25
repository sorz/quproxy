use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use tokio::time::{interval_at, Instant};
use tracing::{debug, info, instrument, trace, warn};

use crate::app::AppContext;

use super::{server::ReferredSocksServer, SocksServerReferrer};

#[derive(Debug)]
pub(crate) struct SocksReferService {
    context: AppContext,
    check_interval: Duration,
    referred_servers: HashMap<Arc<SocksServerReferrer>, ReferredSocksServer>,
}

impl SocksReferService {
    pub(crate) fn new(context: AppContext, check_interval: Duration) -> Self {
        Self {
            context,
            check_interval,
            referred_servers: Default::default(),
        }
    }

    pub(crate) async fn launch(mut self) -> ! {
        let mut interval = interval_at(Instant::now(), self.check_interval);
        loop {
            interval.tick().await;
            self.check_all().await;
        }
    }

    #[instrument(skip_all)]
    async fn check_all(&mut self) {
        debug!("Start checking all SOCKSv5 server referrers");
        // Remove dead connections
        let mut dead_referrers = HashSet::new();
        let mut dead_servers = HashSet::new();
        for (referrer, referred) in &self.referred_servers {
            trace!("Checking {} ({:?})", referrer.name, referred.stream);
            if let Err(err) = referred.stream.readable().await {
                info!(
                    "SOCKSv5 [{}]({:?}) disconnected: {}",
                    referrer.name, referred.stream, err
                );
                dead_referrers.insert(referrer.clone());
                dead_servers.insert(referred.server.clone());
            }
        }
        self.referred_servers
            .retain(|key, _| !dead_referrers.contains(key));

        // Start new connections
        let mut new_servers = HashSet::new();
        for referrer in self.context.socks5_referrers() {
            if !self.referred_servers.contains_key(&referrer) {
                match referrer.negotiate().await {
                    Ok(referred) => {
                        info!(
                            "Connected with {}, UDP endpoint {:?}",
                            referrer.name, referred.server.udp_addr
                        );
                        new_servers.insert(referred.server.clone());
                        self.referred_servers.insert(referrer, referred);
                    }
                    Err(err) => warn!("Failed to negotiate with {}: {}", referrer.name, err),
                }
            }
        }

        // Update SOCKSv5 servers
        let mut servers = self.context.update_socks5_servers();
        servers.retain(|server| !dead_servers.contains(server) && !new_servers.contains(server));
        servers.extend(new_servers.into_iter());
    }
}
