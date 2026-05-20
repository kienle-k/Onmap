use std::str::FromStr;

/// Parses the Time-To-Live (TTL) value from the string output of a ping command.
///
/// This function is designed to be robust by searching for a case-insensitive "ttl="
/// pattern within the input string. It can handle common output formats from both
/// Linux/macOS and Windows `ping` utilities.
///
/// # Arguments
///
/// * `output` - A string slice (`&str`) representing the console output of a ping command.
///
/// # Returns
///
/// An `Option<u8>` which is:
/// * `Some(ttl)` if a valid TTL value was found and parsed successfully.
/// * `None` if the "ttl=" pattern was not found, or if the value following it was not a valid number.
///
/// # Examples
///
/// ```
/// # use onmap::resolving::extract_ttl::extract_ttl;
///
/// // Linux-style output
/// let linux_output = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=12.3 ms";
/// assert_eq!(extract_ttl(linux_output), Some(58));
///
/// // Windows-style output
/// let windows_output = "Reply from 8.8.8.8: bytes=32 time=22ms TTL=117";
/// assert_eq!(extract_ttl(windows_output), Some(117));
///
/// // No TTL present
/// let no_ttl_output = "Request timed out.";
/// assert_eq!(extract_ttl(no_ttl_output), None);
/// ```
pub fn extract_ttl(output: &str) -> Option<u8> {
    // Iterate through each line to find the one containing the TTL info.
    for line in output.lines() {
        // Convert to lowercase for case-insensitive matching (e.g., "ttl=" vs "TTL=").
        let lowercase_line = line.to_lowercase();
        if let Some(ttl_index) = lowercase_line.find("ttl=") {
            // Get the part of the string immediately after "ttl=".
            let ttl_part = &lowercase_line[(ttl_index + 4)..]; // Skip past "ttl="

            // Find the end of the number by looking for the first non-digit character.
            let end_of_number = ttl_part
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(ttl_part.len());

            // Attempt to parse the numeric slice into a u8.
            if let Ok(ttl) = u8::from_str(&ttl_part[..end_of_number]) {
                return Some(ttl); // Return the first valid TTL found.
            }
        }
    }
    // If no valid TTL was found in any line, return None.
    None
}

#[cfg(test)]
mod tests {
    //! Unit tests for the `extract_ttl` function.
    use super::*;

    /// Verifies TTL extraction from a standard Linux ping response.
    #[test]
    fn test_standard_linux_output() {
        let output = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=12.3 ms";
        assert_eq!(extract_ttl(output), Some(58));
    }

    /// Verifies TTL extraction from a standard Windows ping response.
    #[test]
    fn test_standard_windows_output() {
        let output = "Reply from 8.8.8.8: bytes=32 time=22ms TTL=117";
        assert_eq!(extract_ttl(output), Some(117));
    }

    /// Ensures that the "ttl=" pattern matching is case-insensitive.
    #[test]
    fn test_case_insensitivity() {
        let output = "some data here tTl=42 another thing";
        assert_eq!(extract_ttl(output), Some(42));
    }

    /// Checks if the TTL can be parsed correctly when it's the last thing on the line.
    #[test]
    fn test_ttl_at_end_of_line() {
        let output = "REPLY FROM 192.168.1.1 WITH TTL=64";
        assert_eq!(extract_ttl(output), Some(64));
    }

    /// Verifies that the function can find the TTL in a multi-line string.
    #[test]
    fn test_multiline_output_with_ttl() {
        let output = "Pinging google.com [142.250.72.14]\n\
                      Reply from 142.250.72.14: bytes=32 time=10ms TTL=118\n\
                      Ping statistics for 142.250.72.14:";
        assert_eq!(extract_ttl(output), Some(118));
    }

    /// Ensures the function returns None when no "ttl=" pattern is present.
    #[test]
    fn test_no_ttl_present() {
        let output = "Request timed out.";
        assert_eq!(extract_ttl(output), None);
    }

    /// Ensures the function handles an empty input string gracefully.
    #[test]
    fn test_empty_string_input() {
        let output = "";
        assert_eq!(extract_ttl(output), None);
    }

    /// Checks that a non-numeric value after "ttl=" results in None.
    #[test]
    fn test_malformed_ttl_value() {
        let output = "some garbage with ttl=abc and more";
        assert_eq!(extract_ttl(output), None);
    }

    /// Checks that the function returns None if "ttl=" is not followed by a value.
    #[test]
    fn test_ttl_followed_by_no_value() {
        let output = "ttl=";
        assert_eq!(extract_ttl(output), None);
    }

    /// Ensures that the function correctly parses the first valid TTL it finds.
    #[test]
    fn test_ttl_with_other_text_containing_ttl() {
        let output = "some text that says little about ttl=55 and that is all";
        assert_eq!(extract_ttl(output), Some(55));
    }

    /// Verifies that the maximum possible u8 TTL value is parsed correctly.
    #[test]
    fn test_max_ttl_value() {
        let output = "this is a test with ttl=255";
        assert_eq!(extract_ttl(output), Some(255));
    }
}
