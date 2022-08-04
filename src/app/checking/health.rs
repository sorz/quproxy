use std::{cell::Cell, collections::VecDeque, fmt::Display, num::NonZeroU8, time::Duration};

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
    cached_score: Cell<Option<i16>>,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            delay_history: VecDeque::with_capacity(DELAY_MAX_HISTORY),
            cached_score: None.into(),
        }
    }
}

impl Display for Health {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(delay) = self.average_delay() {
            write!(
                f,
                "[{:#.1?} {}% {}]",
                delay,
                self.loss_percent(),
                self.score()
            )
        } else {
            write!(f, "[unknown ({})]", self.score())
        }
    }
}

impl Health {
    pub(super) fn add_measurement(&mut self, delay: Option<Delay>) {
        if self.delay_history.len() >= DELAY_MAX_HISTORY {
            self.delay_history.pop_front();
        }
        self.delay_history.push_back(delay);
        self.cached_score.take();
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

    pub(super) fn score(&self) -> i16 {
        if let Some(score) = self.cached_score.get() {
            score
        } else if let Some(delay) = self.average_delay() {
            let delay_ms = delay.as_millis().clamp(10, 2000) as f32;
            let loss_rate = self.loss_percent().clamp(0, 99) as f32 / 100.0;
            let score = (delay_ms + loss_rate * 1000.0) / (1.0 - loss_rate).powf(2.0);
            let score = score.clamp(i16::MIN as f32, i16::MAX as f32).round() as i16;
            self.cached_score.replace(Some(score));
            score
        } else {
            i16::MAX
        }
    }
}
