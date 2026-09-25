//! Electron's fuse wire: a sentinel string followed by one byte per fuse, which
//! `@electron/fuses` flips in place on a built binary. Disabling
//! `EnableEmbeddedAsarIntegrityValidation` there is a single byte, and needs none of
//! the disassembly the `ValidateIntegrityOrDie` stub relies on.

use log::info;

use crate::{Error, Result};

/// Marks the start of the fuse wire. Electron embeds it verbatim.
const SENTINEL: &[u8] = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";

/// Index of `EnableEmbeddedAsarIntegrityValidation` in the v1 wire.
const ASAR_INTEGRITY: usize = 4;

const FUSE_DISABLED: u8 = b'0';
const FUSE_ENABLED: u8 = b'1';
/// Written by Electron for a fuse that this build does not have at all.
const FUSE_REMOVED: u8 = b'\r';

/// Disables ASAR integrity validation by flipping its fuse, returning whether a
/// byte was written. An already-disabled fuse is a no-op, so this is idempotent
/// and safe to re-run over an exe patched by an earlier run.
pub fn disable_asar_integrity(data: &mut [u8]) -> Result<bool> {
    let sentinel_at = data
        .windows(SENTINEL.len())
        .position(|w| w == SENTINEL)
        .ok_or(Error::FuseSentinelNotFound)?;

    // The sentinel is followed by a version byte and the wire length.
    let wire_at = sentinel_at + SENTINEL.len() + 2;
    let wire_len = *data.get(wire_at - 1).ok_or(Error::FuseWireTruncated)? as usize;
    if ASAR_INTEGRITY >= wire_len {
        return Err(Error::FuseWireTruncated);
    }

    let fuse = data.get_mut(wire_at + ASAR_INTEGRITY).ok_or(Error::FuseWireTruncated)?;
    match *fuse {
        FUSE_DISABLED => {
            info!("ASAR integrity fuse already disabled");
            Ok(false)
        }
        FUSE_REMOVED => {
            info!("ASAR integrity fuse is not present in this build");
            Ok(false)
        }
        FUSE_ENABLED => {
            *fuse = FUSE_DISABLED;
            info!("Disabled the ASAR integrity fuse at file 0x{:x}", wire_at + ASAR_INTEGRITY);
            Ok(true)
        }
        other => Err(Error::FuseUnexpected(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal fuse wire with the given bytes, embedded in some padding.
    fn wire(bytes: &[u8]) -> Vec<u8> {
        let mut v = vec![0xAA; 16];
        v.extend_from_slice(SENTINEL);
        v.push(1); // version
        v.push(bytes.len() as u8);
        v.extend_from_slice(bytes);
        v.extend_from_slice(&[0xBB; 16]);
        v
    }

    #[test]
    fn flips_an_enabled_fuse() {
        let mut data = wire(b"010011011");
        assert!(disable_asar_integrity(&mut data).unwrap());
        let at = 16 + SENTINEL.len() + 2 + ASAR_INTEGRITY;
        assert_eq!(data[at], FUSE_DISABLED);
        // Only that one byte moved.
        assert_eq!(&data[at + 1..at + 5], b"1011");
        assert_eq!(&data[16 + SENTINEL.len() + 2..at], b"0100");
    }

    #[test]
    fn already_disabled_is_a_noop() {
        let mut data = wire(b"010001011");
        assert!(!disable_asar_integrity(&mut data).unwrap());
        assert_eq!(data, wire(b"010001011"));
    }

    #[test]
    fn removed_fuse_is_a_noop() {
        let mut data = wire(b"0100\r1011");
        assert!(!disable_asar_integrity(&mut data).unwrap());
    }

    #[test]
    fn missing_sentinel_errors() {
        let mut data = vec![0u8; 256];
        assert!(matches!(
            disable_asar_integrity(&mut data),
            Err(Error::FuseSentinelNotFound)
        ));
    }

    #[test]
    fn short_wire_errors() {
        let mut data = wire(b"010");
        assert!(matches!(
            disable_asar_integrity(&mut data),
            Err(Error::FuseWireTruncated)
        ));
    }
}
