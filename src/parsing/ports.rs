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