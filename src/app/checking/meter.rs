use std::{collections::VecDeque, time::Instant};

use crate::app::socks5::{SocksServer, Traffic};

use super::Healthy;

const MAX_SAMPLES: usize = 6;

#[derive(Debug)]
pub(crate) struct Meter {
    samples: VecDeque<Sample>,
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
            samples: VecDeque::with_capacity(MAX_SAMPLES),
        }
    }
}

impl Meter {
    fn add_sample(&mut self, traffic: Traffic) {
        while self.samples.len() >= MAX_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(traffic.into());
    }

    fn evaluate_trouble_state(&self) -> Option<bool> {
        if self.samples.len() < MAX_SAMPLES {
            return None;
        }
        let mut last = *self.samples.front().unwrap();
        let mut cnt_tx = 0;
        let mut cnt_rx = 0;
        self.samples.iter().skip(1).copied().for_each(|cur| {
            let amt = cur.traffic - last.traffic;
            if amt.tx_bytes > 0 {
                cnt_tx += 1;
            }
            if amt.rx_bytes > 0 {
                cnt_rx += 1;
            }
            last = cur;
        });
        // In trouble if TX occur in >= 1/2 samplings while no single RX
        if cnt_tx >= MAX_SAMPLES / 2 && cnt_rx == 0 {
            Some(true)
        // Not in trouble if any RX occur.
        } else if cnt_rx > 0 {
            Some(false)
        } else {
            None // Undeciable
        }
    }
}

pub(super) trait Sampling {
    fn sample_traffic(&self);
}

impl Sampling for SocksServer {
    fn sample_traffic(&self) {
        let mut meter = self.status.meter.lock();
        meter.add_sample(self.status.usage.traffic.get());
        if let Some(trouble) = meter.evaluate_trouble_state() {
            self.set_troubleness(trouble);
        }
    }
}
