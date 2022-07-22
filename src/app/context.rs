use parking_lot::RwLock;
use std::{collections::HashSet, sync::Arc};
use tracing::{info, warn};

use super::socks5::SocksServer;
use crate::cli::CliArgs;

#[derive(Debug, Clone)]
pub(crate) struct AppContext {
    socks5_servers: Arc<RwLock<Vec<Arc<SocksServer>>>>,
}

impl AppContext {
    pub(crate) fn from_cli_args(args: &CliArgs) -> Self {
        let mut socks5_udp = HashSet::with_capacity(args.socks5_udp.len());
        let socks5_servers: Vec<_> = args
            .socks5_udp
            .iter()
            .filter_map(|addr| {
                if socks5_udp.contains(addr) {
                    warn!("Duplicated SOCKSv5 UDP server: {:?}", addr);
                    None
                } else {
                    socks5_udp.insert(addr);
                    Some(SocksServer::new(*addr, None).into())
                }
            })
            .collect();
        info!("Configured SOCKSv5 servers: {}", socks5_servers.len());
        if socks5_servers.is_empty() {
            warn!("No proxy server configured");
        }
        Self {
            socks5_servers: RwLock::new(socks5_servers).into(),
        }
    }

    pub(crate) fn socks5_servers(&self) -> Vec<Arc<SocksServer>> {
        self.socks5_servers.read().clone()
    }
}
