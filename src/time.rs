use chrono::{DateTime, Utc};

/// A trait to abstract fetching the current time.
#[cfg_attr(test, mockall::automock)]
pub trait TimeService: Send + Sync + 'static {
    /// Returns the current UTC timestamp.
    fn current_time(&self) -> DateTime<Utc>;
}

/// A time service that uses the system clock.
pub struct DefaultTimeService;

impl TimeService for DefaultTimeService {
    fn current_time(&self) -> DateTime<Utc> {
        Utc::now()
    }
}
