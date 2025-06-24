use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use hyper::http::StatusCode;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn verify_signature(
    path: &str,
    query: Option<&str>,
    sign_token: &str,
    range_header: Option<&str>,
) -> Result<(), StatusCode> {
    let query = query.unwrap_or("");
    let parsed = serde_querystring::DuplicateQS::parse(query.as_bytes());

    // Parse signature from query parameter $
    let sign_param = parsed
        .values(b"$")
        .and_then(|v| v.first().cloned().unwrap_or(None));

    // If no signature parameter is found, return an error
    let sign_param = sign_param.ok_or(StatusCode::PAYMENT_REQUIRED)?;

    // Extract the signature string - avoid extra allocation
    let sign_bytes = sign_param.as_ref();

    // Parse signature components: {4byte hex unix过期时间}{hmac_sha256_hex}{4byte hex range start}{4byte hex range end}...
    // Minimum length: 8 (expire) + 64 (hmac) + 0 (no range) = 72 hex chars
    if sign_bytes.len() < 72 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Parse expire time from first 8 hex chars
    let expire_time = parse_hex_u32(&sign_bytes[0..8]).ok_or(StatusCode::BAD_REQUEST)? as u64;

    // Check expiration
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if current_time > expire_time {
        return Err(StatusCode::PAYMENT_REQUIRED);
    }

    // Extract HMAC from bytes 8-72 (64 hex chars)
    let hmac_hex = &sign_bytes[8..72];
    if hmac_hex.len() != 64 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Parse ranges from remaining bytes (starting at position 72)
    let ranges_bytes = &sign_bytes[72..];
    if ranges_bytes.len() % 16 != 0 {
        // Each range is 16 hex chars (8 for start + 8 for end)
        return Err(StatusCode::BAD_REQUEST);
    }

    // Parse all ranges
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < ranges_bytes.len() {
        let range_start = parse_hex_u32(&ranges_bytes[i..i + 8]).ok_or(StatusCode::BAD_REQUEST)?;
        let range_end =
            parse_hex_u32(&ranges_bytes[i + 8..i + 16]).ok_or(StatusCode::BAD_REQUEST)?;
        ranges.push((range_start, range_end));
        i += 16;
    } // Build HMAC message: /path/to/file\n{4byte hex unix过期时间}\n{ranges...}
    let mut message = format!("{}\n{:08x}\n", path, expire_time as u32);
    for (start, end) in &ranges {
        message.push_str(&format!("{:08x}{:08x}", start, end));
    }

    // Verify Range header matches signature ranges if provided
    if let Some(range_header_value) = range_header {
        let parsed_ranges = parse_range_header(range_header_value)?;
        if parsed_ranges != ranges {
            return Err(StatusCode::BAD_REQUEST);
        }
    } else if !ranges.is_empty() {
        // If signature contains ranges but no Range header is provided, it's invalid
        return Err(StatusCode::BAD_REQUEST);
    }

    // Verify HMAC
    let mut mac = HmacSha256::new_from_slice(sign_token.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    let expected_hmac = mac.finalize().into_bytes();

    // Parse received HMAC from hex
    let mut expected_hex = [0u8; 64];
    hex::encode_to_slice(expected_hmac, &mut expected_hex).unwrap();

    if hmac_hex != expected_hex {
        return Err(StatusCode::PAYMENT_REQUIRED);
    }

    Ok(())
}

/// Create a signature string for a given path, expiration time and optional ranges
///
/// # Arguments
/// * `path` - The file path to sign
/// * `expire_time` - Unix timestamp when the signature expires
/// * `sign_token` - The signing key
/// * `ranges` - Optional list of (start, end) byte ranges
///
/// # Returns
/// Returns a signature string in the format: {expire_time}{hmac}{ranges...}
pub fn create_signature(
    path: &str,
    expire_time: u32,
    sign_token: &str,
    ranges: Option<&[(u32, u32)]>,
) -> String {
    // Build HMAC message: /path/to/file\n{4byte hex unix过期时间}\n{ranges...}
    let mut message = format!("{}\n{:08x}\n", path, expire_time);

    if let Some(ranges) = ranges {
        for (start, end) in ranges {
            message.push_str(&format!("{:08x}{:08x}", start, end));
        }
    }

    // Calculate HMAC
    let mut mac = HmacSha256::new_from_slice(sign_token.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    let hmac_bytes = mac.finalize().into_bytes();

    // Convert HMAC to hex
    let hmac_hex = hex::encode(hmac_bytes);

    // Build signature string: {expire_time}{hmac}{ranges...}
    let mut signature = format!("{:08x}{}", expire_time, hmac_hex);

    if let Some(ranges) = ranges {
        for (start, end) in ranges {
            signature.push_str(&format!("{:08x}{:08x}", start, end));
        }
    }

    signature
}

/// Helper function to get current Unix timestamp + offset seconds
pub fn get_expire_time(offset_seconds: u32) -> u32 {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    (current_time + offset_seconds as u64) as u32
}

// Helper function to parse hex without allocation
fn parse_hex_u32(hex_bytes: &[u8]) -> Option<u32> {
    if hex_bytes.len() != 8 {
        return None;
    }

    let mut result = 0u32;
    for &byte in hex_bytes {
        result <<= 4;
        match byte {
            b'0'..=b'9' => result |= (byte - b'0') as u32,
            b'a'..=b'f' => result |= (byte - b'a' + 10) as u32,
            b'A'..=b'F' => result |= (byte - b'A' + 10) as u32,
            _ => return None,
        }
    }
    Some(result)
}

// Helper function to parse Range header
fn parse_range_header(range_header: &str) -> Result<Vec<(u32, u32)>, StatusCode> {
    // Expected format: "bytes=start1-end1,start2-end2,..."
    if !range_header.starts_with("bytes=") {
        return Err(StatusCode::BAD_REQUEST);
    }

    let ranges_str = &range_header[6..]; // Skip "bytes="
    let mut ranges = Vec::new();

    for range_part in ranges_str.split(',') {
        let range_part = range_part.trim();
        if let Some(dash_pos) = range_part.find('-') {
            let start_str = &range_part[..dash_pos];
            let end_str = &range_part[dash_pos + 1..];

            // Parse start and end, handling empty values
            let start = if start_str.is_empty() {
                0
            } else {
                start_str
                    .parse::<u32>()
                    .map_err(|_| StatusCode::BAD_REQUEST)?
            };

            let end = if end_str.is_empty() {
                u32::MAX
            } else {
                end_str
                    .parse::<u32>()
                    .map_err(|_| StatusCode::BAD_REQUEST)?
            };

            ranges.push((start, end));
        } else {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    Ok(ranges)
}
