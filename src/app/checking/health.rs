use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tracing::{debug, info};

use crate::app::{checking::PING_MAX_RETRY, socks5::SocksServer, AppContext, InnerProto};

use super::ping::Pingable;

#[derive(Debug, Default)]
pub(crate) struct Health {
    in_trouble: AtomicBool,
}

pub(crate) trait Healthy {
    fn is_healthy(&self) -> bool;
    fn set_troubleness(&self, trouble: bool);
}

impl Healthy for SocksServer {
    fn is_healthy(&self) -> bool {
        !self.status.health.in_trouble.load(Ordering::Relaxed)
    }

    fn set_troubleness(&self, trouble: bool) {
        let old = self
            .status
            .health
            .in_trouble
            .swap(trouble, Ordering::Relaxed);
        match (old, trouble) {
            (false, true) => info!("Upstream [{}] goes trouble", self.name),
            (true, false) => info!("Upstream [{}] goes out of trouble", self.name),
            _ => (),
        };
    }
}

impl SocksServer {
    pub(super) async fn check_troubleness(self: &Arc<Self>, context: &AppContext) -> bool {
        debug!("Checking [{}]", self.name);
        let dns4 = context.cli_args.check_dns_server_v4.into();
        let dns6 = context.cli_args.check_dns_server_v6.into();
        let result = match self.inner_proto.get() {
            InnerProto::Unspecified => {
                tokio::select! {
                    r = self.ping_with_dns_query(dns4, PING_MAX_RETRY) => r,
                    r = self.ping_with_dns_query(dns6, PING_MAX_RETRY) => r,
                }
            }
            InnerProto::IPv4 | InnerProto::Inet => {
                self.ping_with_dns_query(dns4, PING_MAX_RETRY).await
            }
            InnerProto::IPv6 => self.ping_with_dns_query(dns6, PING_MAX_RETRY).await,
        };
        match result {
            Err(_) | Ok(None) => true,
            Ok(Some(_)) => false,
        }
    }
}
