use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Default, Debug)]
pub(crate) struct Usage {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    session_active: AtomicUsize,
    session_total: AtomicUsize,
}

impl Usage {
    pub(super) fn open_session(&self) {
        self.session_total.fetch_add(1, Ordering::Relaxed);
        self.session_active.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn close_session(&self) {
        self.session_active.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    pub(super) fn add_tx(&self, bytes: usize) {
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub(super) fn add_rx(&self, bytes: usize) {
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}
