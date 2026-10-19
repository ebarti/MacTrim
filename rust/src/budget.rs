//! Cooperative worker pacing. Idle time is never charged as active work.
use anyhow::Result;
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub struct Budget {
    percent: AtomicU8,
    clock: Mutex<Instant>,
}
impl Budget {
    pub fn new(percent: u8) -> Self {
        Self {
            percent: AtomicU8::new(percent.clamp(1, 100)),
            clock: Mutex::new(Instant::now()),
        }
    }
    pub fn set_percent(&self, percent: u8) {
        self.percent.store(percent.clamp(1, 100), Ordering::Relaxed);
    }
    pub fn begin(&self) {
        *self.clock.lock().unwrap() = Instant::now();
    }
    fn pause_for(active: Duration, percent: u8) -> Duration {
        active.mul_f64(f64::from(100 - percent) / f64::from(percent))
    }
    pub fn checkpoint(&self, cancel: &AtomicBool) -> Result<()> {
        crate::scan::check_cancelled(cancel)?;
        let percent = self.percent.load(Ordering::Relaxed);
        let mut clock = self.clock.lock().unwrap();
        let active = clock.elapsed();
        if percent == 100 || active < Duration::from_millis(10) {
            return Ok(());
        }
        let until = Instant::now() + Self::pause_for(active, percent);
        while let Some(remaining) = until.checked_duration_since(Instant::now()) {
            crate::scan::check_cancelled(cancel)?;
            if self.percent.load(Ordering::Relaxed) == 100 {
                break;
            }
            thread::sleep(remaining.min(Duration::from_millis(20)));
        }
        *clock = Instant::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn budget_computes_duty_cycle_without_timing_benchmarks() {
        assert_eq!(
            Budget::pause_for(Duration::from_millis(10), 10),
            Duration::from_millis(90)
        );
        assert_eq!(
            Budget::pause_for(Duration::from_millis(10), 25),
            Duration::from_millis(30)
        );
        assert_eq!(
            Budget::pause_for(Duration::from_millis(10), 100),
            Duration::ZERO
        );
        assert!(
            Budget::new(10)
                .checkpoint(&AtomicBool::new(true))
                .unwrap_err()
                .is::<crate::scan::Cancelled>()
        );
    }
}
