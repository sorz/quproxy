use std::sync::atomic::{AtomicBool, Ordering};

use tracing::info;

use crate::app::socks5::SocksServer;

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
