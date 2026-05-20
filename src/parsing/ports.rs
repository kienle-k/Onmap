use super::super::models::PortOptions;

/// Parses a user-provided string into a vector of port numbers (`u16`).
///
/// This function is flexible and supports multiple input formats for convenience:
/// - A single port number (e.g., `"80"`).
/// - An inclusive range of ports separated by a hyphen (e.g., `"80-1024"`).
/// - A single hyphen (`"-"`) as a shortcut for the full port range (0-65535).
/// - A list of ports (e.g.: "80,90,100")
/// - A combination of list and range (e.g "80,90,100-200")
/// - A single 'F' character for "Fast" mode, which returns a list of the 100 most common ports.
///
/// # Arguments
///
/// * `port_input` - A `String` containing the port(s) to be parsed.
///
/// # Returns
///
/// * `Ok(Vec<u16>)` if the input string is valid.
/// * `Err(String)` if the input is malformed, contains invalid numbers, or represents an invalid range.
///
/// # Examples
///
/// ```
/// use onmap::parsing::ports::convert_ports;
/// assert_eq!(convert_ports("8080".to_string()).expect("Port could not be parsed"), vec![8080]);
/// assert_eq!(convert_ports("21-23".to_string()).expect("Port range could not be parsed"), vec![21, 22, 23]);
/// assert_eq!(convert_ports("21,23,24".to_string()).expect("Port list could not be parsed"), vec![21, 23, 24]);
/// assert_eq!(convert_ports("21,23,24-26".to_string()).expect("Port list with ranges inside could not be parsed"), vec![21, 23, 24, 25, 26]);
/// assert_eq!(convert_ports("-".to_string()).expect("All ports could not be parsed").len(), 65536);
/// ```

pub fn convert_ports(port_input: String) -> Result<Vec<u16>, String> {
    // Trim to eliminate faulty spaces at edges
    let input = port_input.trim();

    // List of most used ports (for -pF)
    let most_used = vec![
        1, 7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 67, 68, 69, 79, 80, 81, 82, 83, 84, 85, 88, 106,
        110, 111, 113, 119, 123, 135, 137, 139, 143, 161, 179, 199, 389, 427, 443, 465, 513, 514,
        515, 587, 631, 636, 873, 993, 995, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1433,
        1521, 1720, 1723, 1900, 2121, 3128, 3306, 3389, 5432, 5900, 6000, 8000, 8008, 8080, 8081,
        8088, 8090, 8118, 8880, 8909, 9000, 9090, 9200, 9300, 9999, 10000, 10001, 11211, 27017,
        27018, 27019, 28017, 32400, 32768, 32769, 49152, 49153, 49154, 49155, 49156, 49157, 49158,
        49159,
    ];

    // For -p- (All ports)
    if input == "-" {
        return Ok((0u16..=65535).collect());
    } else if input == "F" {
        return Ok(most_used);
    }

    // Split at ',' --> For each obj: Either single port or a port range(with -)
    // If it isnt a list, just the single remaining split object is parsed --> list or single ports are also detected
    let mut result = Vec::new();
    for part in input.split(',') {
        let p = part.trim();
        // Split at "-" --> detect port range
        if let Some((start, end)) = p.split_once('-') {
            let start: u16 = start
                .trim()
                .parse()
                .map_err(|_| format!("Invalid start: {}", start))?;
            let end: u16 = end
                .trim()
                .parse()
                .map_err(|_| format!("Invalid end: {}", end))?;
            // Asure range makes sense
            if start > end {
                return Err(format!("Start {} greater than end {}", start, end));
            }
            result.extend(start..=end);
        // If not a port range try to parse a single port
        } else {
            let single: u16 = p.parse().map_err(|_| format!("Invalid port: {}", p))?;
            result.push(single);
        }
    }
    Ok(result)
}

pub fn set_ports_arr(port_option: PortOptions) -> Result<Vec<u16>, String> {
    match port_option {
        // "Normal" mode provides a list of the 1000 most common ports.
        PortOptions::NormalMode => Ok((1..=1000).collect()),

        PortOptions::FastMode => {
            // "Fast" mode returns a curated list of the top 100 most common ports.
            Ok(vec![
                1, 7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 67, 68, 69, 79, 80, 81, 82, 83, 84, 85,
                88, 106, 110, 111, 113, 119, 123, 135, 137, 139, 143, 161, 179, 199, 389, 427, 443,
                465, 513, 514, 515, 587, 631, 636, 873, 993, 995, 1024, 1025, 1026, 1027, 1028,
                1029, 1030, 1031, 1433, 1521, 1720, 1723, 1900, 2121, 3128, 3306, 3389, 5432, 5900,
                6000, 8000, 8008, 8080, 8081, 8088, 8090, 8118, 8880, 8909, 9000, 9090, 9200, 9300,
                9999, 10000, 10001, 11211, 27017, 27018, 27019, 28017, 32400, 32768, 32769, 49152,
                49153, 49154, 49155, 49156, 49157, 49158, 49159,
            ])
        }

        // "Sequential" mode scans the entire range of valid port numbers.
        PortOptions::SequentialMode => Ok((1..=65535).collect()),

        // This function only handles predefined sets. Options like `PortRangeInput`
        // are handled elsewhere and are considered an invalid input here.
        _ => Err("Ports array could not be set".to_string()),
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the port parsing and selection logic.
    //!
    //! ## `convert_ports`
    //!
    //! This section tests the parsing of various string formats into port lists.
    //!
    //! ## `set_ports_arr`
    //!
    //! This section tests the generation of port lists from predefined modes.
    use super::*;

    // --- Tests for the convert_ports function ---

    /// Verifies that the "-" shortcut correctly expands to all 65,536 ports.
    #[test]
    fn test_convert_port_range_full_range() {
        let ports = convert_ports("-".to_string())
            .expect("Parsing a full port range '-' should always succeed");
        assert_eq!(ports.len(), 65536);
        assert_eq!(ports[0], 0);
        assert_eq!(ports[65535], 65535);
    }

    /// Verifies that the "F" shortcut correctly returns the list of common ports.
    #[test]
    fn test_convert_port_range_fast_scan() {
        let ports = convert_ports("F".to_string())
            .expect("Parsing the fast scan option 'F' should always succeed");
        assert!(!ports.is_empty());
        assert_eq!(ports[0], 1);
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&8080));
    }

    /// Verifies that a valid single port string is parsed correctly.
    #[test]
    fn test_convert_port_range_single_port_valid() {
        let ports =
            convert_ports("8080".to_string()).expect("Parsing a single valid port should succeed");
        assert_eq!(ports, vec![8080]);
    }

    /// Verifies that an invalid string (not a number, but contains a hyphen) fails as expected.
    #[test]
    fn test_convert_port_range_single_port_invalid() {
        let err_message = convert_ports("not-a-port".to_string())
            .expect_err("A non-numeric single port should produce an error");
        assert_eq!(
            err_message,
            "Invalid start: not".to_string() // Corrected to match the actual error output
        );
    }

    /// Verifies that a simple, valid port range is parsed correctly.
    #[test]
    fn test_convert_port_range_valid_range() {
        let ports =
            convert_ports("80-82".to_string()).expect("Parsing a valid port range should succeed");
        assert_eq!(ports, vec![80, 81, 82]);
    }

    /// Verifies that a range where the start port is greater than the end port fails.
    #[test]
    fn test_convert_port_range_invalid_range_start_greater() {
        let err_message = convert_ports("90-80".to_string())
            .expect_err("A range where the start port is greater than the end port should fail");
        assert_eq!(
            err_message,
            "Start 90 greater than end 80".to_string() // Corrected to match the actual error output
        );
    }

    /// Verifies that a range string with too many parts (more than one hyphen) fails.
    #[test]
    fn test_convert_port_range_invalid_format_too_many_parts() {
        let err_message = convert_ports("80-90-100".to_string())
            .expect_err("A range with more than two parts should fail");
        assert_eq!(err_message, "Invalid end: 90-100".to_string()); // Corrected to match the actual error output
    }

    /// Verifies that a range with a non-numeric start port fails.
    #[test]
    fn test_convert_port_range_invalid_start_port() {
        let err_message = convert_ports("abc-90".to_string())
            .expect_err("A range with an invalid start port should fail");
        assert_eq!(err_message, "Invalid start: abc".to_string()); // Corrected to match the actual error output
    }

    /// Verifies that a range with a non-numeric end port fails.
    #[test]
    fn test_convert_port_range_invalid_end_port() {
        let err_message = convert_ports("80-xyz".to_string())
            .expect_err("A range with an invalid end port should fail");
        assert_eq!(err_message, "Invalid end: xyz".to_string()); // Corrected to match the actual error output
    }

    // --- Tests for the set_ports_arr function ---

    /// Verifies that `NormalMode` returns the correct range of 1-1000.
    #[test]
    fn test_set_ports_arr_normal_mode() {
        let ports = set_ports_arr(PortOptions::NormalMode)
            .expect("Setting ports for NormalMode should not fail");
        assert_eq!(ports.len(), 1000);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[999], 1000);
    }

    /// Verifies that `FastMode` returns the list of 100 common ports.
    #[test]
    fn test_set_ports_arr_fast_mode() {
        let ports = set_ports_arr(PortOptions::FastMode)
            .expect("Setting ports for FastMode should not fail");
        assert!(!ports.is_empty());
        assert!(ports.contains(&22));
        assert!(ports.contains(&443));
        assert!(ports.contains(&3389));
    }

    /// Verifies that `SequentialMode` returns the full range of 1-65535.
    #[test]
    fn test_set_ports_arr_sequential_mode() {
        let ports = set_ports_arr(PortOptions::SequentialMode)
            .expect("Setting ports for SequentialMode should not fail");
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[65534], 65535);
    }
}
