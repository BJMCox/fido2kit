//! FIDO2 security-key code and the vault slot store, shared by fido2kpxc, fido2lock, and fido2tomb.

mod app;
pub mod fido;
#[cfg(feature = "vault")]
pub mod vault;

pub use app::App;
