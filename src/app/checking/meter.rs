use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

use parking_lot::Mutex;
use tracing::info;

use crate::app::socks5::{SocksServer, Traffic};

const MAX_SAMPLES: usize = 5;

#[derive(Debug)]
pub(crate) struct Meter {
    samples: Mutex<VecDeque<Sample>>,
    in_trouble: AtomicBool,
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    time: Instant,
    traffic: Traffic,
}

impl From<Traffic> for Sample {
    fn from(traffic: Traffic) -> Self {
        Self {
            time: Instant::now(),
            traffic,
        }
    }
}

impl Default for Meter {
    fn default() -> Self {
        Self {
            samples: VecDeque::with_capacity(MAX_SAMPLES).into(),
            in_trouble: false.into(),
        }
    }
}

impl Meter {
    fn add_sample(&self, traffic: Traffic) {
        let mut samples = self.samples.lock();
        while samples.len() >= MAX_SAMPLES {
            samples.pop_front();
        }
        samples.push_back(traffic.into());
    }

    fn evaluate_trouble_state(&self) -> Option<bool> {
        let samples = self.samples.lock();
        if samples.len() < MAX_SAMPLES {
            return None;
        }
        let mut last = *samples.front().unwrap();
        let mut cnt_tx = 0;
        let mut cnt_rx = 0;
        samples.iter().skip(1).copied().for_each(|cur| {
            let amt = cur.traffic - last.traffic;
            if amt.tx_bytes > 0 {
                cnt_tx += 1;
            }
            if amt.rx_bytes > 0 {
                cnt_rx += 1;
            }
            last = cur;
        });
        // Set `in_trouble` if TX occur in all samplings while no single RX
        if cnt_tx >= MAX_SAMPLES && cnt_rx == 0 {
            if !self.in_trouble.swap(true, Ordering::Relaxed) {
                return Some(true);
            }
        // Unset if any RX occur.
        } else if cnt_rx > 0 && self.in_trouble.swap(false, Ordering::Relaxed) {
            return Some(false);
        }
        None
    }
}

pub(super) trait Sampling {
    fn sample_traffic(&self);
}

impl Sampling for Arc<SocksServer> {
    fn sample_traffic(&self) {
        let meter = &self.status.meter;
        meter.add_sample(self.status.usage.traffic.get());
        if let Some(trouble) = meter.evaluate_trouble_state() {
            if trouble {
                info!("Upstream [{}] goes trouble", self.name);
            } else {
                info!("Upstream [{}] goes out of trouble", self.name);
            }
        }
    }
}

pub(crate) trait Health {
    fn is_healthy(&self) -> bool;
}

impl Health for Arc<SocksServer> {
    #[inline]
    fn is_healthy(&self) -> bool {
        !self.status.meter.in_trouble.load(Ordering::Relaxed)
    }
}
