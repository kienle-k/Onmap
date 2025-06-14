use std::str::FromStr;

/// Extract TTL value from ping output
pub fn extract_ttl(output: &str) -> Option<u8> {
    // Try to find TTL in the output
    // For Linux: "ttl=64"
    // For Windows: "TTL=64"
    for line in output.lines() {
        let lowercase_line = line.to_lowercase();
        if lowercase_line.contains("ttl=") {
            // Find position of "ttl=" and extract the value after it
            if let Some(ttl_index) = lowercase_line.find("ttl=") {
                let ttl_part = &lowercase_line[(ttl_index + 4)..]; // Skip past "ttl="
                if let Some(end_index) = ttl_part.find(|c: char| !c.is_ascii_digit()) {
                    // Extract just the numeric part
                    if let Ok(ttl) = u8::from_str(&ttl_part[..end_index]) {
                        return Some(ttl);
                    }
                } else {
                    // If no non-digit found, use the whole remaining string
                    if let Ok(ttl) = u8::from_str(ttl_part) {
                        return Some(ttl);
                    }
                }
            }
        }
    }
    None
}


#[cfg(test)]
mod tests {
    use super::*; // Import the extract_ttl function from the parent module

    #[test]
    fn test_standard_linux_output() {
        let output = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=12.3 ms";
        assert_eq!(extract_ttl(output), Some(58));
    }

    #[test]
    fn test_standard_windows_output() {
        let output = "Reply from 8.8.8.8: bytes=32 time=22ms TTL=117";
        assert_eq!(extract_ttl(output), Some(117));
    }

    #[test]
    fn test_case_insensitivity() {
        let output = "some data here tTl=42 another thing";
        assert_eq!(extract_ttl(output), Some(42));
    }

    #[test]
    fn test_ttl_at_end_of_line() {
        let output = "REPLY FROM 192.168.1.1 WITH TTL=64";
        assert_eq!(extract_ttl(output), Some(64));
    }

    #[test]
    fn test_multiline_output_with_ttl() {
        let output = "Pinging google.com [142.250.72.14]\n\
                      Reply from 142.250.72.14: bytes=32 time=10ms TTL=118\n\
                      Ping statistics for 142.250.72.14:";
        assert_eq!(extract_ttl(output), Some(118));
    }

    #[test]
    fn test_no_ttl_present() {
        let output = "Request timed out.";
        assert_eq!(extract_ttl(output), None);
    }

    #[test]
    fn test_empty_string_input() {
        let output = "";
        assert_eq!(extract_ttl(output), None);
    }

    #[test]
    fn test_malformed_ttl_value() {
        let output = "some garbage with ttl=abc and more";
        assert_eq!(extract_ttl(output), None);
    }

    #[test]
    fn test_ttl_followed_by_no_value() {
        let output = "ttl=";
        assert_eq!(extract_ttl(output), None);
    }

    #[test]
    fn test_ttl_with_other_text_containing_ttl() {
        // Ensures it finds the first valid one and stops.
        let output = "some text that says little about ttl=55 and that is all";
        assert_eq!(extract_ttl(output), Some(55));
    }
    
    #[test]
    fn test_max_ttl_value() {
        let output = "this is a test with ttl=255";
        assert_eq!(extract_ttl(output), Some(255));
    }
}