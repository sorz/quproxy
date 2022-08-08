use std::{
    fmt::Display,
    ops::Sub,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use bytesize::ByteSize;

#[derive(Default, Debug)]
pub(crate) struct Usage {
    pub(crate) traffic: AtomicTraffic,
    session_active: AtomicUsize,
    session_total: AtomicUsize,
}

#[derive(Default, Debug)]
pub(crate) struct AtomicTraffic {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct Traffic {
    pub(crate) tx_bytes: u64,
    pub(crate) rx_bytes: u64,
}

impl Display for Traffic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TX {}, RX {}",
            ByteSize(self.tx_bytes),
            ByteSize(self.rx_bytes)
        )
    }
}

impl Sub for Traffic {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::Output {
            tx_bytes: self
                .tx_bytes
                .checked_sub(rhs.tx_bytes)
                .expect("negtive TX bytes"),
            rx_bytes: self
                .rx_bytes
                .checked_sub(rhs.rx_bytes)
                .expect("negtive RX bytes"),
        }
    }
}

impl AtomicTraffic {
    #[inline]
    pub(super) fn add_tx(&self, bytes: usize) {
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub(super) fn add_rx(&self, bytes: usize) {
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn get(&self) -> Traffic {
        Traffic {
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
        }
    }
}

impl Usage {
    pub(super) fn open_session(&self) {
        self.session_total.fetch_add(1, Ordering::Relaxed);
        self.session_active.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn close_session(&self) {
        self.session_active.fetch_sub(1, Ordering::Relaxed);
    }
}
