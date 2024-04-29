/// The `constants` module defines constant values used across the application.
/// It includes constants for key and salt sizes.

/// The size of the key in bytes.
/// This constant is used in key derivation functions.
pub(crate) const KEY_BYTES: usize = 32;

/// The size of the salt in bytes.
/// This constant is used in salt generation functions.
pub(crate) const SALT_BYTES: usize = 32;