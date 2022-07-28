use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::Arc,
};

use derivative::Derivative;
use tokio::time::{interval_at, Instant};
use tracing::{debug, info, instrument, trace, warn};

use super::{server::ReferredSocksServer, SocksServerReferrer};
use crate::app::AppContext;

#[derive(Derivative, Debug)]
pub(crate) struct SocksReferService<S> {
    #[derivative(Debug = "ignore")]
    context: AppContext<S>,
    referred_servers: HashMap<Arc<SocksServerReferrer>, ReferredSocksServer<S>>,
}

impl<S: Default> SocksReferService<S> {
    pub(crate) fn new(context: AppContext<S>) -> Self {
        Self {
            context,
            referred_servers: Default::default(),
        }
    }

    pub(crate) async fn launch(mut self) -> ! {
        let mut interval = interval_at(
            Instant::now(),
            self.context.cli_args.socks5_tcp_check_interval,
        );
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
            if let Entry::Vacant(entry) = self.referred_servers.entry(referrer) {
                match entry.key().negotiate().await {
                    Ok(referred) => {
                        info!(
                            "Connected with {}, UDP endpoint {:?}",
                            entry.key().name,
                            referred.server.udp_addr
                        );
                        new_servers.insert(referred.server.clone());
                        entry.insert(referred);
                    }
                    Err(err) => warn!("Failed to negotiate with {}: {}", entry.key().name, err),
                }
            }
        }

        // Update SOCKSv5 servers
        let mut servers = self.context.update_socks5_servers();
        servers.retain(|server| !dead_servers.contains(server) && !new_servers.contains(server));
        servers.extend(new_servers.into_iter());
    }
}
