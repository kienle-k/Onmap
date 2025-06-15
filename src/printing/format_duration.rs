use std::time::Duration;

/// Formats a `Duration` into a more human-readable string.
///
/// This helper function displays durations in milliseconds if they are less than a second,
/// or in a "seconds and milliseconds" format for longer durations.
///
/// # Arguments
///
/// * `duration` - A reference to the `Duration` to be formatted.
///
/// # Returns
///
/// A `String` representing the formatted duration (e.g., "<1ms", "15ms", "2s 543ms").
///
/// # Examples
///
/// ```
/// # use std::time::Duration;
/// # use onmap::printing::format_duration::format_duration;
///
/// let d = Duration::from_millis(1234);
/// assert_eq!(format_duration(&d), "1s 234ms");
///
/// let d_short = Duration::from_millis(56);
/// assert_eq!(format_duration(&d_short), "56ms");
/// ```
pub fn format_duration(duration: &Duration) -> String {
    let total_millis = duration.as_millis();
    if total_millis < 1 {
        format!("<1ms")
    } else if total_millis < 1000 {
        format!("{}ms", total_millis)
    } else {
        let seconds = total_millis / 1000;
        let millis = total_millis % 1000;
        format!("{}s {}ms", seconds, millis)
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the `format_duration` helper function.
    use super::*;

    /// Tests formatting for durations that are less than one millisecond.
    #[test]
    fn test_format_duration_less_than_one_ms() {
        let duration = Duration::from_nanos(500_000);
        assert_eq!(format_duration(&duration), "<1ms");
    }

    /// Tests formatting for a duration of exactly zero.
    #[test]
    fn test_format_duration_exact_zero() {
        let duration = Duration::from_millis(0);
        assert_eq!(format_duration(&duration), "<1ms");
    }

    /// Tests formatting for a simple duration under one second.
    #[test]
    fn test_format_duration_simple_ms() {
        let duration = Duration::from_millis(15);
        assert_eq!(format_duration(&duration), "15ms");
    }

    /// Tests the upper boundary of the millisecond-only format.
    #[test]
    fn test_format_duration_almost_one_second() {
        let duration = Duration::from_millis(999);
        assert_eq!(format_duration(&duration), "999ms");
    }

    /// Tests the format for exactly one second.
    #[test]
    fn test_format_duration_one_second() {
        let duration = Duration::from_millis(1000);
        assert_eq!(format_duration(&duration), "1s 0ms");
    }

    /// Tests the format for a duration greater than one second with a millisecond component.
    #[test]
    fn test_format_duration_seconds_and_ms() {
        let duration = Duration::from_millis(2543);
        assert_eq!(format_duration(&duration), "2s 543ms");
    }
}