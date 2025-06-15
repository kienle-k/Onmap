use std::time::Duration;

// Helper function to format Duration in a readable way
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
    use super::*;

    // Unit tests for the `format_duration` helper function
    #[test]
    fn test_format_duration_less_than_one_ms() {
        let duration = Duration::from_nanos(500_000);
        assert_eq!(format_duration(&duration), "<1ms");
    }

    #[test]
    fn test_format_duration_exact_zero() {
        let duration = Duration::from_millis(0);
        assert_eq!(format_duration(&duration), "<1ms");
    }

    #[test]
    fn test_format_duration_simple_ms() {
        let duration = Duration::from_millis(15);
        assert_eq!(format_duration(&duration), "15ms");
    }

    #[test]
    fn test_format_duration_almost_one_second() {
        let duration = Duration::from_millis(999);
        assert_eq!(format_duration(&duration), "999ms");
    }

    #[test]
    fn test_format_duration_one_second() {
        let duration = Duration::from_millis(1000);
        assert_eq!(format_duration(&duration), "1s 0ms");
    }

    #[test]
    fn test_format_duration_seconds_and_ms() {
        let duration = Duration::from_millis(2543);
        assert_eq!(format_duration(&duration), "2s 543ms");
    }
}