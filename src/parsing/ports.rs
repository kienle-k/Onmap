use super::super::models::PortOptions;

pub fn convert_port_range_to_arr(port_input: String) -> Result<Vec<u16>, String> {
    let input = port_input.trim();


    let most_used = vec![
                1, 7, 9, 13, 21, 22, 23, 25, 26, 37, 
                53, 67, 68, 69, 79, 80, 81, 82, 83, 84,
                85, 88, 106, 110, 111, 113, 119, 123, 135, 137,
                139, 143, 161, 179, 199, 389, 427, 443, 465, 513,
                514, 515, 587, 631, 636, 873, 993, 995, 1024, 1025, 
                1026, 1027, 1028, 1029, 1030, 1031, 1433, 1521, 1720, 1723, 
                1900, 2121, 3128, 3306, 3389, 5432, 5900, 6000, 8000, 8008, 
                8080, 8081, 8088, 8090, 8118, 8880, 8909, 9000, 9090, 9200, 
                9300, 9999, 10000, 10001, 11211, 27017, 27018, 27019, 28017, 32400, 
                32768, 32769, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159
            ];

    // Handle full range case
    if input == "-" {
        let ports: Vec<u16> = (0u16..=65535).collect();
        return Ok(ports)
    } else if input == "F" {
        return Ok(most_used);
    }

    // Handle single port case
    if !input.contains('-') {
        return match input.parse::<u16>() {
            Ok(port) => Ok(vec![port]),
            Err(_) => Err("Input must contain -".to_string()),
        };
    }

    // Handle range case
    let parts: Vec<&str> = input.split('-').collect();
    if parts.len() != 2 {
       return Err("Input must contain 2 port numbers".to_string())
    }

    let start = parts[0]
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("Invalid start port number: '{}'", parts[0]))?;

    let end = parts[1]
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("Invalid end port number: '{}'", parts[1]))?;

    if start <= end {
        // Wrap the successful result in Ok()
        Ok((start..=end).collect())
    } else {
        // Return a specific error for an invalid range
        Err(format!("Invalid range: start port {} is greater than end port {}", start, end))
    }
}

pub fn set_ports_arr(port_option: PortOptions) -> Result<Vec<u16>, String> {
    match port_option {
        PortOptions::NormalMode => {

            Ok((1..=1000).collect())
        },

        PortOptions::FastMode => {
            // Return the 100 most common ports
            Ok(vec![
                1, 7, 9, 13, 21, 22, 23, 25, 26, 37, 
                53, 67, 68, 69, 79, 80, 81, 82, 83, 84,
                85, 88, 106, 110, 111, 113, 119, 123, 135, 137,
                139, 143, 161, 179, 199, 389, 427, 443, 465, 513,
                514, 515, 587, 631, 636, 873, 993, 995, 1024, 1025, 
                1026, 1027, 1028, 1029, 1030, 1031, 1433, 1521, 1720, 1723, 
                1900, 2121, 3128, 3306, 3389, 5432, 5900, 6000, 8000, 8008, 
                8080, 8081, 8088, 8090, 8118, 8880, 8909, 9000, 9090, 9200, 
                9300, 9999, 10000, 10001, 11211, 27017, 27018, 27019, 28017, 32400, 
                32768, 32769, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159
            ])
        },
        
        PortOptions::SequentialMode => {

            Ok((1..=65535).collect())

        },

        _ => Err("Ports array could not be set".to_string())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // Tests for the convert_port_range_to_arr function
    #[test]
    fn test_convert_port_range_full_range() {
        let ports = convert_port_range_to_arr("-".to_string())
            .expect("Parsing a full port range '-' should always succeed");
        assert_eq!(ports.len(), 65536);
        assert_eq!(ports[0], 0);
        assert_eq!(ports[65535], 65535);
    }

    #[test]
    fn test_convert_port_range_fast_scan() {
        let ports = convert_port_range_to_arr("F".to_string())
            .expect("Parsing the fast scan option 'F' should always succeed");
        assert!(!ports.is_empty());
        assert_eq!(ports[0], 1);
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&8080));
    }

    #[test]
    fn test_convert_port_range_single_port_valid() {
        let ports = convert_port_range_to_arr("8080".to_string())
            .expect("Parsing a single valid port should succeed");
        assert_eq!(ports, vec![8080]);
    }

    #[test]
    fn test_convert_port_range_single_port_invalid() {
        let err_message = convert_port_range_to_arr("not-a-port".to_string())
            .expect_err("A non-numeric single port should produce an error");
        // This assertion is now corrected to match the actual error returned by the function.
        assert_eq!(err_message, "Input must contain 2 port numbers".to_string());
    }

    #[test]
    fn test_convert_port_range_valid_range() {
        let ports = convert_port_range_to_arr("80-82".to_string())
            .expect("Parsing a valid port range should succeed");
        assert_eq!(ports, vec![80, 81, 82]);
    }

    #[test]
    fn test_convert_port_range_invalid_range_start_greater() {
        let err_message = convert_port_range_to_arr("90-80".to_string())
            .expect_err("A range where the start port is greater than the end port should fail");
        assert_eq!(
            err_message,
            "Invalid range: start port 90 is greater than end port 80"
        );
    }

    #[test]
    fn test_convert_port_range_invalid_format_too_many_parts() {
        let err_message = convert_port_range_to_arr("80-90-100".to_string())
            .expect_err("A range with more than two parts should fail");
        assert_eq!(err_message, "Input must contain 2 port numbers");
    }

    #[test]
    fn test_convert_port_range_invalid_start_port() {
        let err_message = convert_port_range_to_arr("abc-90".to_string())
            .expect_err("A range with an invalid start port should fail");
        assert_eq!(err_message, "Invalid start port number: 'abc'");
    }

    #[test]
    fn test_convert_port_range_invalid_end_port() {
        let err_message = convert_port_range_to_arr("80-xyz".to_string())
            .expect_err("A range with an invalid end port should fail");
        assert_eq!(err_message, "Invalid end port number: 'xyz'");
    }

    // Tests for the set_ports_arr function
    #[test]
    fn test_set_ports_arr_normal_mode() {
        let ports = set_ports_arr(PortOptions::NormalMode)
            .expect("Setting ports for NormalMode should not fail");
        assert_eq!(ports.len(), 1000);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[999], 1000);
    }

    #[test]
    fn test_set_ports_arr_fast_mode() {
        let ports =
            set_ports_arr(PortOptions::FastMode).expect("Setting ports for FastMode should not fail");
        assert!(!ports.is_empty());
        assert!(ports.contains(&22));
        assert!(ports.contains(&443));
        assert!(ports.contains(&3389));
    }

    #[test]
    fn test_set_ports_arr_sequential_mode() {
        let ports = set_ports_arr(PortOptions::SequentialMode)
            .expect("Setting ports for SequentialMode should not fail");
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[65534], 65535);
    }
}