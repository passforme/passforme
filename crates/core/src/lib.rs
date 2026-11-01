//! Vault format, cryptography and password generator.
//!
//! This crate performs no I/O: every secret enters and leaves through
//! function arguments, which keeps it testable and reviewable in isolation.

// Macros first: `macro_rules!` is visible only to the modules declared after it.

/// Public random identifiers: not secret, stored in the clear.
macro_rules! public_bytes {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            pub fn generate<R: ::rand_core::CryptoRng + ?Sized>(rng: &mut R) -> Self {
                let mut bytes = [0u8; $len];
                rng.fill_bytes(&mut bytes);
                Self(bytes)
            }

            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }
    };
}

/// Key material kept on the heap (moving the value moves only the pointer),
/// wiped on drop, never printed.
macro_rules! secret_bytes {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        pub struct $name(Box<[u8; $len]>);

        impl $name {
            pub(crate) fn zeroed() -> Self {
                Self(Box::new([0u8; $len]))
            }

            pub(crate) fn expose(&self) -> &[u8; $len] {
                &self.0
            }

            pub(crate) fn expose_mut(&mut self) -> &mut [u8; $len] {
                &mut self.0
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                ::zeroize::Zeroize::zeroize(&mut *self.0);
            }
        }

        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

pub mod api;
pub mod bip39;
pub mod generator;
pub mod item;
pub mod kdf;
pub mod kind;
pub mod kit;
pub mod seal;
pub mod sync;
pub mod totp;
pub mod vault;
