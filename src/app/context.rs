use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use derivative::Derivative;
use parking_lot::{RwLock, RwLockWriteGuard};
use tracing::{info, warn};

use super::socks5::{SocksServer, SocksServerReferrer};
use crate::cli::CliArgs;

#[derive(Derivative)]
#[derivative(Debug, Clone(bound = ""))]
pub(crate) struct AppContext<Status> {
    socks5_servers: Arc<RwLock<Vec<Arc<SocksServer<Status>>>>>,
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

impl<Status: Default> AppContext<Status> {
    pub(crate) fn from_cli_args(args: &CliArgs) -> Self {
        let socks5_servers: Vec<Arc<_>> = filter_duplicated_socket_addrs(&args.socks5_udp)
            .into_iter()
            .map(|addr| SocksServer::new(addr, None).into())
            .collect();
        let socks5_referrers: Vec<Arc<_>> = filter_duplicated_socket_addrs(&args.socks5_tcp)
            .into_iter()
            .map(|addr| SocksServerReferrer::new(addr, None).into())
            .collect();
        info!(
            "Configured SOCKSv5 servers: {}",
            socks5_servers.len() + socks5_referrers.len()
        );
        if socks5_servers.is_empty() && socks5_referrers.is_empty() {
            warn!("No proxy server configured");
        }
        Self {
            socks5_servers: RwLock::new(socks5_servers).into(),
            socks5_referrers: RwLock::new(socks5_referrers).into(),
        }
    }

    pub(crate) fn socks5_servers(&self) -> Vec<Arc<SocksServer<Status>>> {
        self.socks5_servers.read().clone()
    }

    pub(crate) fn socks5_referrers(&self) -> Vec<Arc<SocksServerReferrer>> {
        self.socks5_referrers.read().clone()
    }

    pub(crate) fn update_socks5_servers(&self) -> RwLockWriteGuard<Vec<Arc<SocksServer<Status>>>> {
        self.socks5_servers.write()
    }
}
