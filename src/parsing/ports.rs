use super::super::models::PortOptions;

pub fn convert_port_range_to_arr(port_input: String) -> Vec<u16> {
    // Split the input string by the '-' character
    let parts: Vec<&str> = port_input.split('-').collect();
    
    // Return empty vector if format is incorrect
    if parts.len() != 2 {
        return Vec::new();
    }
    
    // Parse the start and end ports
    let start = match parts[0].trim().parse::<u16>() {
        Ok(num) => num,
        Err(_) => return Vec::new(), // Return empty vector if parsing fails
    };
    
    let end = match parts[1].trim().parse::<u16>() {
        Ok(num) => num,
        Err(_) => return Vec::new(), // Return empty vector if parsing fails
    };
    
    // Create a vector with all ports in the range (inclusive)
    if start <= end {
        (start..=end).collect()
    } else {
        Vec::new()
    }
}

pub fn set_ports_arr(port_option: PortOptions) -> Vec<u16> {
    match port_option {
        PortOptions::FastMode => {
            // Return the 100 most common ports
            vec![
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
            ]
        },
        PortOptions::SequentialMode => {
            // Return all ports from 1 to 65535 in order
            (1..=65535).collect()
        },
        PortOptions::NormalMode => {

            let mut ports: Vec<u16> = (1..=65535).collect();
            
            // Fisher-Yates shuffle algorithm to randomize the array
            use rand::Rng;
            let mut rng = rand::thread_rng();
            
            for i in (1..ports.len()).rev() {
                let j = rng.gen_range(0..=i);
                ports.swap(i, j);
            }
            
            ports
        },
        _ => Vec::new(),
    }
}