/// The app a credential or vault belongs to. Its name is the FIDO2 relying-party ID and the vault
/// domain, so one value keeps the two from drifting apart. Two apps must never share a name: a
/// shared relying-party ID would let one app's key entries unwrap in the other's vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct App(&'static str);

impl App {
    /// Panics unless `name` is non-empty and only `a-z` and `0-9`. Apps build it in a `const`, so a
    /// bad name fails the build. The limit keeps vault AAD strings unambiguous and keeps path
    /// separators out of temp-file names.
    pub const fn new(name: &'static str) -> Self {
        let bytes = name.as_bytes();
        assert!(!bytes.is_empty(), "An app name is never empty");
        let mut i = 0;
        while i < bytes.len() {
            assert!(
                bytes[i].is_ascii_lowercase() || bytes[i].is_ascii_digit(),
                "An app name holds only a-z and 0-9"
            );
            i += 1;
        }
        Self(name)
    }

    pub const fn name(self) -> &'static str {
        self.0
    }
}

#[cfg(test)]
mod tests;
