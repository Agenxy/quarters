//! Shared acceptance-test compatibility helpers.

use std::path::Path;

pub(crate) fn pre_alpha4_runtime_fingerprint(path: &Path) -> u64 {
    let mut hash = 14_695_981_039_346_656_037_u64;
    for byte in path.as_os_str().as_encoded_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(1_099_511_628_211);
    }
    hash
}
