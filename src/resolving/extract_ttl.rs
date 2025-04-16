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