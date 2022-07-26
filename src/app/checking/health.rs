use std::{collections::VecDeque, num::NonZeroU8, time::Duration};

const DELAY_POWER: f32 = 0.75;
const DELAY_MAX_HISTORY: usize = 100;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Delay(NonZeroU8);

impl From<Duration> for Delay {
    fn from(t: Duration) -> Self {
        let v = (t.as_millis() as f32).powf(DELAY_POWER).round() as u8;
        Self(v.try_into().unwrap_or_else(|_| 1.try_into().unwrap()))
    }
}

impl From<Delay> for Duration {
    fn from(d: Delay) -> Self {
        Duration::from_millis(d.as_millis() as u64)
    }
}

impl Delay {
    pub(crate) fn as_millis(&self) -> u16 {
        (self.0.get() as f32).powf(1.0 / DELAY_POWER) as u16
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Health {
    delay_history: VecDeque<Option<Delay>>,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            delay_history: VecDeque::with_capacity(DELAY_MAX_HISTORY),
        }
    }
}

impl Health {
    pub(crate) fn add_measurement(&mut self, delay: Option<Delay>) {
        if self.delay_history.len() >= DELAY_MAX_HISTORY {
            self.delay_history.pop_front();
        }
        self.delay_history.push_back(delay);
    }

    pub(crate) fn loss_percent(&self) -> u8 {
        let lost = self
            .delay_history
            .iter()
            .copied()
            .filter(Option::is_none)
            .count();
        ((lost as f32) / (self.delay_history.len() as f32) * 100.0).round() as u8
    }

    pub(crate) fn average_delay(&self) -> Option<Duration> {
        let (count, sum) =
            self.delay_history
                .iter()
                .copied()
                .fold((0usize, 0u32), |(count, sum), x| match x {
                    Some(delay) => (count + 1, sum + delay.as_millis() as u32),
                    None => (count, sum),
                });
        if count == 0 {
            None
        } else {
            Duration::from_millis(sum as u64 / count as u64).into()
        }
    }
}
