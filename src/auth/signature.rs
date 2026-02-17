use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use http::StatusCode;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Holds the HMAC secret and exposes signature verification.
#[derive(Clone)]
pub struct SignatureVerifier {
    sign_token: String,
}

impl SignatureVerifier {
    pub fn new(sign_token: &str) -> Self {
        Self {
            sign_token: sign_token.to_string(),
        }
    }

    /// Verify a signature string against the given path and optional Range header.
    ///
    /// `sign_str` is the raw value of the `$` query parameter (already extracted by the caller).
    /// Returns `Ok(())` on success or a descriptive error string on failure.
    pub fn verify(
        &self,
        path: &str,
        sign_str: &str,
        range_header: Option<&str>,
    ) -> Result<(), String> {
        verify_signature(path, sign_str, &self.sign_token, range_header)
    }
}

/// Core verification logic.
///
/// `sign_str` format: `{32B uuid}{8B hex expire}{64B hmac hex}{16B per range pair}...`
fn verify_signature(
    path: &str,
    sign_str: &str,
    sign_token: &str,
    range_header: Option<&str>,
) -> Result<(), String> {
    let sign_bytes = sign_str.as_bytes();

    // Minimum length: 32 (uuid) + 8 (expire) + 64 (hmac) = 104
    if sign_bytes.len() < 104 {
        return Err("signature too short".into());
    }

    // Extract UUID from first 32 hex chars
    let uuid = &sign_bytes[0..32];

    // Parse expire time from next 8 hex chars (32..40)
    let expire_time =
        parse_hex_u32(&sign_bytes[32..40]).ok_or("invalid expire hex")? as u64;

    // Check expiration
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if current_time > expire_time {
        return Err("signature expired".into());
    }

    // Extract HMAC from bytes 40..104 (64 hex chars)
    let hmac_hex = &sign_bytes[40..104];

    // Parse ranges from remaining bytes (starting at 104), each range is 16 hex chars
    let ranges_bytes = &sign_bytes[104..];
    if !ranges_bytes.len().is_multiple_of(16) {
        return Err("invalid range length in signature".into());
    }

    let mut ranges = Vec::new();
    let mut i = 0;
    while i < ranges_bytes.len() {
        let range_start =
            parse_hex_u32(&ranges_bytes[i..i + 8]).ok_or("invalid range start hex")?;
        let range_end =
            parse_hex_u32(&ranges_bytes[i + 8..i + 16]).ok_or("invalid range end hex")?;
        ranges.push((range_start, range_end));
        i += 16;
    }

    // Build HMAC message: {uuid}\n{path}\n{8byte hex expire}\n{ranges...}
    let uuid_str = std::str::from_utf8(uuid).map_err(|_| "invalid uuid encoding")?;
    let mut message = format!("{}\n{}\n{:08x}\n", uuid_str, path, expire_time as u32);
    for (start, end) in &ranges {
        message.push_str(&format!("{:08x}{:08x}", start, end));
    }

    // Verify Range header matches signature ranges
    if !ranges.is_empty() {
        let Some(range_header_value) = range_header else {
            return Err("signature has ranges but no Range header provided".into());
        };
        let parsed_ranges =
            parse_range_header(range_header_value).map_err(|_| "invalid Range header")?;
        if parsed_ranges != ranges {
            return Err("Range header does not match signature ranges".into());
        }
    }
    // If signature has no ranges, any Range header is fine (or none)

    // Verify HMAC
    let mut mac = HmacSha256::new_from_slice(sign_token.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    let expected_hmac = mac.finalize().into_bytes();

    let mut expected_hex = [0u8; 64];
    hex::encode_to_slice(expected_hmac, &mut expected_hex).unwrap();

    if hmac_hex != expected_hex {
        return Err("HMAC mismatch".into());
    }

    Ok(())
}

/// Create a signature string for a given path, expiration time and optional ranges
pub fn create_signature(
    uuid: &str,
    path: &str,
    expire_time: u32,
    sign_token: &str,
    ranges: Option<&[(u32, u32)]>,
) -> String {
    // Build HMAC message: {uuid}\n/path/to/file\n{8byte hex expire}\n{ranges...}
    let mut message = format!("{}\n{}\n{:08x}\n", uuid, path, expire_time);

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

    // Build signature string: {uuid}{expire_time}{hmac}{ranges...}
    let mut signature = format!("{}{:08x}{}", uuid, expire_time, hmac_hex);

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
