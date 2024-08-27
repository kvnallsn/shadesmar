use std::ffi::{c_char, CStr};

use error::WanError;
use serde::de::DeserializeOwned;

pub mod error;

/// Attempts to covert a string of (null-terminated) bytes into a CStr
/// 
/// ### Returns
/// * `Some(str)` - If str is not null
/// * `None` - If str is null
/// 
/// ### Arguments
/// * `str` - Bytes to parse as a str
pub fn parse_cstr<'a>(str: *const c_char) -> Option<&'a CStr> {
    // SAFETY: we check for the nullptr above
    // BUT it is critical that the string is null-terminated otherwise we might have issues
    match str.is_null() {
        true => None,
        false => Some(unsafe { CStr::from_ptr(str) }),
    }
}

/// Deserializes a configuration for a WAN adapter
/// 
/// Takes the raw c-style string passed to this plugin and attempts
/// to deserialize the specified WAN config type.
/// 
/// ### Arguments
/// * `cfg` - Config string as a sequence of (null-terminated) bytes
///  
/// ### Returns
/// * `Ok(Some(cfg))` - If deserialization was successful
/// * `Ok(None)` - If a nullptr or empty string was passed as the config
/// * `Err(error)` - If any of the above fails
pub fn load_config<D: DeserializeOwned>(cfg: *const c_char) -> Result<Option<D>, WanError> {
    if cfg.is_null() {
        return Ok(None);
    }

    // SAFETY: we check for the nullptr above
    // BUT it is critical that the string is null-terminated otherwise we might have issues
    let cfg = unsafe { CStr::from_ptr(cfg) };
    let cfg = cfg.to_str()?;
    let cfg: D = serde_json::from_str(cfg)?;

    Ok(Some(cfg))
}