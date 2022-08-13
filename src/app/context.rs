use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use derivative::Derivative;
use lru_time_cache::LruCache;
use parking_lot::RwLock;
use tracing::{info, warn};

use super::socks5::{SocksServer, SocksServerReferrer};
use crate::cli::{CliArgs, ConfigFile, Upstream, UpstreamProtocol};

#[derive(Derivative)]
#[derivative(Debug, Clone(bound = ""))]
pub(crate) struct AppContext {
    pub(crate) cli_args: &'static CliArgs,
    socks5_servers: Arc<RwLock<Vec<Arc<SocksServer>>>>,
    socks5_referrers: Arc<RwLock<Vec<Arc<SocksServerReferrer>>>>,
}

fn filter_duplicated_socket_addrs(addrs: &Vec<SocketAddr>) -> HashSet<SocketAddr> {
    let mut set = HashSet::with_capacity(addrs.len());
    for addr in addrs {
        if !set.insert(*addr) {
            warn!("Ignore duplicated address: {:?}", addr);
        }
    }
    set
}

impl AppContext {
    pub(crate) fn from_cli_args(args: CliArgs) -> Self {
        let mut socks5_servers: Vec<Arc<_>> = filter_duplicated_socket_addrs(&args.socks5_udp)
            .into_iter()
            .map(|addr| Arc::new(addr.into()))
            .collect();
        let mut socks5_referrers: Vec<Arc<_>> = filter_duplicated_socket_addrs(&args.socks5_tcp)
            .into_iter()
            .map(|addr| Arc::new(addr.into()))
            .collect();

        // TODO: check duplicated socket address & name
        // TODO: retain order
        if let Some(path) = &args.list {
            let cfg = ConfigFile::from_path(path).expect("Error on read upstream list file");
            for (
                name,
                Upstream {
                    protocol,
                    address,
                    enabled,
                    inner_proto,
                },
            ) in cfg.upstreams
            {
                if !enabled {
                    continue;
                }
                match protocol {
                    UpstreamProtocol::Socks5Udp => {
                        socks5_servers.push(SocksServer::new(address, name, inner_proto).into())
                    }
                    UpstreamProtocol::Socks5Tcp => socks5_referrers
                        .push(SocksServerReferrer::new(address, name, inner_proto).into()),
                }
            }
        }

        info!(
            "Configured SOCKSv5 servers: {}",
            socks5_servers.len() + socks5_referrers.len()
        );
        if socks5_servers.is_empty() && socks5_referrers.is_empty() {
            warn!("No proxy server configured");
        }
        Self {
            cli_args: Box::leak(args.into()),
            socks5_servers: RwLock::new(socks5_servers).into(),
            socks5_referrers: RwLock::new(socks5_referrers).into(),
        }
    }
}

impl AppContext {
    pub(crate) fn new_lru_cache_for_sessions<K, V>(&self) -> LruCache<K, V>
    where
        K: Ord + Clone,
    {
        LruCache::with_expiry_duration_and_capacity(
            self.cli_args.udp_session_timeout,
            self.cli_args.udp_max_sessions,
        )
    }

    pub(crate) fn socks5_servers(&self) -> Vec<Arc<SocksServer>> {
        self.socks5_servers.read().clone()
    }

    pub(crate) fn socks5_referrers(&self) -> Vec<Arc<SocksServerReferrer>> {
        self.socks5_referrers.read().clone()
    }

    pub(crate) fn update_socks5_servers<F, R>(&self, func: F) -> R
    where
        F: FnOnce(&mut Vec<Arc<SocksServer>>) -> R,
    {
        let mut servers = self.socks5_servers.write();
        func(&mut servers)
    }
}
