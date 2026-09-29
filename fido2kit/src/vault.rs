use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::App;
pub use crate::fido::Unlock;

const VERSION: u32 = 2;
/// A vault with a few keys and passwords is a few kilobytes. The bound keeps parsing fast.
const MAX_VAULT_BYTES: u64 = 1 << 20;

/// The name that matches any lookup without its own entry.
pub const ANY: &str = "*";

/// The result of checking a key: its label, and the secrets it opens or not.
pub struct Check {
    pub label: String,
    pub opened: Vec<String>,
    pub failed: Vec<String>,
}

/// Builds only through [`Vault::create`] and [`Vault::parse`], so every vault passes
/// [`Vault::validate`].
#[derive(Serialize)]
pub struct Vault {
    version: u32,
    #[serde(with = "b64")]
    salt: Vec<u8>,
    keys: Vec<KeyEntry>,
    secrets: Vec<SecretEntry>,
    /// The file text this vault was loaded from or last saved as. A save refuses to replace a
    /// file that no longer holds it.
    #[serde(skip)]
    loaded: Option<String>,
    /// Names the AAD, the temp files, and the messages. It never reaches the file.
    #[serde(skip)]
    app: App,
}

/// The version 2 layout as read, before validation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultFile {
    #[allow(dead_code)]
    version: u32,
    #[serde(with = "b64")]
    salt: Vec<u8>,
    keys: Vec<KeyEntry>,
    secrets: Vec<SecretEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    label: String,
    #[serde(with = "b64")]
    cred_id: Vec<u8>,
    #[serde(with = "b64")]
    nonce: Vec<u8>,
    #[serde(with = "b64")]
    wrapped_key: Vec<u8>,
}

/// One stored password. `name` is what the app looks it up by, such as fido2kpxc's `pdb.kdbx`,
/// or [`ANY`]. The file keeps fido2kpxc's field name, so vaults stay byte for byte the same.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretEntry {
    #[serde(rename = "database")]
    name: String,
    #[serde(with = "b64")]
    nonce: Vec<u8>,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
}

/// The version 1 layout: one password, which now loads as the [`ANY`] entry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultV1 {
    #[allow(dead_code)]
    version: u32,
    #[serde(with = "b64")]
    salt: Vec<u8>,
    #[serde(with = "b64")]
    nonce: Vec<u8>,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
    keys: Vec<KeyEntry>,
}

impl Vault {
    pub fn new_salt() -> Result<[u8; 32]> {
        random()
    }

    pub fn create(
        app: App,
        salt: [u8; 32],
        label: &str,
        unlock: &Unlock,
        name: &str,
        secret: &[u8],
    ) -> Result<Self> {
        let key = Zeroizing::new(random::<32>()?);
        let mut vault = Self {
            version: VERSION,
            salt: salt.to_vec(),
            keys: Vec::new(),
            secrets: Vec::new(),
            loaded: None,
            app,
        };
        vault.seal(&key, name, secret)?;
        vault.wrap(&key, label, unlock)?;
        Ok(vault)
    }

    pub fn salt(&self) -> [u8; 32] {
        self.salt.as_slice().try_into().expect("validated on load")
    }

    pub fn cred_ids(&self) -> Vec<&[u8]> {
        self.keys.iter().map(|k| k.cred_id.as_slice()).collect()
    }

    /// Stored secret names, in vault order.
    pub fn names(&self) -> Vec<&str> {
        self.secrets.iter().map(|s| s.name.as_str()).collect()
    }

    /// True when `open` would find a password for `name`.
    pub fn has_secret_for(&self, name: Option<&str>) -> bool {
        self.secret_for(name).is_some()
    }

    /// Decrypts the password for `name`: its own entry if one exists, else the [`ANY`] entry.
    pub fn open(&self, unlock: &Unlock, name: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
        let key = self.unwrap(unlock)?;
        let Some(entry) = self.secret_for(name) else {
            return Err(match name {
                Some(name) => anyhow!("No password is stored for {name}"),
                None => anyhow!("No password is stored"),
            });
        };
        self.decrypt(&key, entry)
    }

    pub fn add_key(&mut self, current: &Unlock, label: &str, new: &Unlock) -> Result<()> {
        ensure!(
            self.keys.iter().all(|k| k.label != label),
            "Label {label:?} already exists"
        );
        ensure!(
            self.keys.iter().all(|k| k.cred_id != new.cred_id),
            "This security key is already enrolled"
        );
        let key = self.unwrap(current)?;
        self.wrap(&key, label, new)
    }

    /// Which enrolled key `unlock` belongs to, and which stored passwords it decrypts.
    pub fn check(&self, unlock: &Unlock) -> Result<Check> {
        let label = self
            .keys
            .iter()
            .find(|k| k.cred_id == unlock.cred_id)
            .context("This security key is not enrolled in the vault")?
            .label
            .clone();
        let key = self.unwrap(unlock)?;
        let (mut opened, mut failed) = (Vec::new(), Vec::new());
        for entry in &self.secrets {
            match self.decrypt(&key, entry) {
                Ok(_) => opened.push(entry.name.clone()),
                Err(_) => failed.push(entry.name.clone()),
            }
        }
        Ok(Check {
            label,
            opened,
            failed,
        })
    }

    /// Labels and credential IDs of the enrolled keys, in vault order.
    pub fn entries(&self) -> Vec<(&str, &[u8])> {
        self.keys
            .iter()
            .map(|k| (k.label.as_str(), k.cred_id.as_slice()))
            .collect()
    }

    /// The labels and credential IDs of the keys that stay after removing `labels`. Fails on an
    /// unknown label, or if no key would stay.
    pub fn kept_keys(&self, labels: &[&str]) -> Result<Vec<(&str, &[u8])>> {
        for label in labels {
            ensure!(
                self.keys.iter().any(|k| k.label == *label),
                "No key is labeled {label:?}"
            );
        }
        let kept: Vec<(&str, &[u8])> = self
            .entries()
            .into_iter()
            .filter(|(label, _)| !labels.contains(label))
            .collect();
        ensure!(!kept.is_empty(), "At least one key must stay enrolled");
        Ok(kept)
    }

    /// Drops the keys in `labels` and moves every password to a new data key.
    /// A removed key that kept an old vault copy knows the old data key, so every
    /// kept key must be present in `remaining` to wrap the new one.
    pub fn remove_keys(&mut self, labels: &[&str], remaining: &[Unlock]) -> Result<()> {
        let kept: Vec<(String, &Unlock)> = self
            .kept_keys(labels)?
            .into_iter()
            .map(|(label, cred_id)| {
                let unlock = remaining
                    .iter()
                    .find(|u| u.cred_id == cred_id)
                    .with_context(|| format!("Key {label:?} must be present"))?;
                // Proves each output is right before the old wrapping is discarded.
                self.unwrap(unlock)?;
                Ok((label.to_owned(), unlock))
            })
            .collect::<Result<_>>()?;
        let old_key = self.unwrap(kept[0].1)?;
        let plain: Vec<(String, Zeroizing<Vec<u8>>)> = self
            .secrets
            .iter()
            .map(|entry| Ok((entry.name.clone(), self.decrypt(&old_key, entry)?)))
            .collect::<Result<_>>()?;
        let key = Zeroizing::new(random::<32>()?);
        self.secrets.clear();
        for (name, secret) in &plain {
            self.seal(&key, name, secret)?;
        }
        self.keys.clear();
        for (label, unlock) in &kept {
            self.wrap(&key, label, unlock)?;
        }
        Ok(())
    }

    /// Adds or replaces the password for `name`.
    pub fn set_secret(&mut self, unlock: &Unlock, name: &str, secret: &[u8]) -> Result<()> {
        let key = self.unwrap(unlock)?;
        self.secrets.retain(|s| s.name != name);
        self.seal(&key, name, secret)
    }

    pub fn remove_secret(&mut self, name: &str) -> Result<()> {
        ensure!(
            self.secrets.iter().any(|s| s.name == name),
            "No password is stored for {name:?}"
        );
        ensure!(
            self.secrets.len() > 1,
            "The vault must keep at least one password"
        );
        self.secrets.retain(|s| s.name != name);
        Ok(())
    }

    pub fn load(app: App, path: &Path) -> Result<Self> {
        let size = std::fs::metadata(path)
            .with_context(|| format!("Cannot read vault {}", path.display()))?
            .len();
        ensure!(
            size <= MAX_VAULT_BYTES,
            "The vault {} is larger than 1 MiB",
            path.display()
        );
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read vault {}", path.display()))?;
        let mut vault =
            Self::parse(app, &text).with_context(|| format!("Invalid vault {}", path.display()))?;
        vault.loaded = Some(text);
        Ok(vault)
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.salt.len() == 32, "The vault salt has the wrong length");
        ensure!(!self.keys.is_empty(), "The vault has no enrolled keys");
        ensure!(!self.secrets.is_empty(), "The vault holds no password");
        ensure!(
            self.keys.iter().all(|k| k.nonce.len() == 24)
                && self.secrets.iter().all(|s| s.nonce.len() == 24),
            "A vault nonce has the wrong length"
        );
        let mut labels = HashSet::new();
        for key in &self.keys {
            ensure!(
                labels.insert(key.label.as_str()),
                "The vault has the label {:?} twice",
                key.label
            );
        }
        let mut cred_ids = HashSet::new();
        ensure!(
            self.keys
                .iter()
                .all(|k| cred_ids.insert(k.cred_id.as_slice())),
            "The vault holds the same security key twice"
        );
        let mut names = HashSet::new();
        ensure!(
            self.secrets.iter().all(|s| names.insert(s.name.as_str())),
            "The vault stores a secret name twice"
        );
        Ok(())
    }

    fn parse(app: App, text: &str) -> Result<Self> {
        let version = toml::from_str::<toml::Table>(text)?
            .get("version")
            .and_then(toml::Value::as_integer)
            .context("The vault has no version")?;
        let vault = match version {
            1 => {
                let v1: VaultV1 = toml::from_str(text)?;
                Self {
                    version: VERSION,
                    salt: v1.salt,
                    keys: v1.keys,
                    secrets: vec![SecretEntry {
                        name: ANY.to_owned(),
                        nonce: v1.nonce,
                        ciphertext: v1.ciphertext,
                    }],
                    loaded: None,
                    app,
                }
            }
            2 => {
                let file: VaultFile = toml::from_str(text)?;
                Self {
                    version: VERSION,
                    salt: file.salt,
                    keys: file.keys,
                    secrets: file.secrets,
                    loaded: None,
                    app,
                }
            }
            other => bail!(
                "The vault has version {other}, from a newer {app}. Update {app}.",
                app = app.name()
            ),
        };
        vault.validate()?;
        Ok(vault)
    }

    /// Replaces the vault atomically. With `create`, refuses to replace an existing file. Without
    /// it, refuses to replace a file that changed since this vault was loaded, so a slow writer
    /// cannot undo another writer's save, such as a key removal.
    pub fn save(&mut self, path: &Path, create: bool) -> Result<()> {
        let dir = path.parent().context("The vault path has no directory")?;
        if create {
            // Creates only the configured folder. A missing parent means a wrong `folder` setting.
            match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
                    return Err(e).with_context(|| format!("Cannot create {}", dir.display()));
                }
                _ => {}
            }
        }
        // A lock on the folder serializes local writers without a file for sync tools to copy.
        let lock =
            std::fs::File::open(dir).with_context(|| format!("Cannot open {}", dir.display()))?;
        // Some network file systems cannot lock (macOS's ENOTSUP 45, EOPNOTSUPP 102). The text
        // comparison below still refuses a stale write there.
        if let Err(e) = lock.lock()
            && e.kind() != std::io::ErrorKind::Unsupported
            && !matches!(e.raw_os_error(), Some(45 | 102))
        {
            return Err(e).with_context(|| format!("Cannot lock {}", dir.display()));
        }
        if !create {
            ensure!(
                std::fs::read_to_string(path).ok() == self.loaded,
                "The vault changed while this ran, for example from another window or computer. Nothing was saved. Try again."
            );
        }
        let text = toml::to_string(self)?;
        // The rename below replaces the vault in one step, so readers never see a partial file.
        let prefix = format!(".{}-", self.app.name());
        let mut temp = tempfile::Builder::new()
            .prefix(&prefix)
            .suffix(".tmp")
            .tempfile_in(dir)?;
        temp.write_all(text.as_bytes())?;
        temp.as_file().sync_all()?;
        if create {
            temp.persist_noclobber(path)?;
        } else {
            temp.persist(path)?;
        }
        self.loaded = Some(text);
        Ok(())
    }

    fn secret_for(&self, name: Option<&str>) -> Option<&SecretEntry> {
        let exact = name.and_then(|name| self.secrets.iter().find(|s| s.name == name));
        exact.or_else(|| self.secrets.iter().find(|s| s.name == ANY))
    }

    fn unwrap(&self, unlock: &Unlock) -> Result<Zeroizing<[u8; 32]>> {
        let entry = self
            .keys
            .iter()
            .find(|k| k.cred_id == unlock.cred_id)
            .context("This security key is not enrolled in the vault")?;
        let payload = Payload {
            msg: &entry.wrapped_key,
            aad: &entry.cred_id,
        };
        let plain = Zeroizing::new(
            cipher(&unlock.output)
                .decrypt(&nonce(&entry.nonce), payload)
                .map_err(|_| anyhow!("Key entry {:?} failed authentication", entry.label))?,
        );
        let key: [u8; 32] = plain
            .as_slice()
            .try_into()
            .context("The wrapped key has the wrong length")?;
        Ok(Zeroizing::new(key))
    }

    fn decrypt(&self, key: &[u8; 32], entry: &SecretEntry) -> Result<Zeroizing<Vec<u8>>> {
        let payload = Payload {
            msg: &entry.ciphertext,
            aad: &secret_aad(self.app, &entry.name),
        };
        cipher(key)
            .decrypt(&nonce(&entry.nonce), payload)
            .map(Zeroizing::new)
            .map_err(|_| anyhow!("The password for {:?} failed authentication", entry.name))
    }

    fn wrap(&mut self, key: &[u8; 32], label: &str, unlock: &Unlock) -> Result<()> {
        let nonce = random::<24>()?;
        let payload = Payload {
            msg: key,
            aad: &unlock.cred_id,
        };
        let wrapped_key = cipher(&unlock.output)
            .encrypt(&XNonce::from(nonce), payload)
            .map_err(|_| anyhow!("Encryption failed"))?;
        self.keys.push(KeyEntry {
            label: label.to_owned(),
            cred_id: unlock.cred_id.clone(),
            nonce: nonce.to_vec(),
            wrapped_key,
        });
        Ok(())
    }

    fn seal(&mut self, key: &[u8; 32], name: &str, secret: &[u8]) -> Result<()> {
        let nonce = random::<24>()?;
        let payload = Payload {
            msg: secret,
            aad: &secret_aad(self.app, name),
        };
        let ciphertext = cipher(key)
            .encrypt(&XNonce::from(nonce), payload)
            .map_err(|_| anyhow!("Encryption failed"))?;
        self.secrets.push(SecretEntry {
            name: name.to_owned(),
            nonce: nonce.to_vec(),
            ciphertext,
        });
        Ok(())
    }
}

/// Binds each password to its app and name, so entries cannot be swapped or moved between apps.
/// The [`ANY`] entry keeps the version 1 value, so migrated vaults need no re-encryption. For
/// fido2kpxc both values are the bytes it always used.
fn secret_aad(app: App, name: &str) -> Vec<u8> {
    if name == ANY {
        format!("{}-vault-v1", app.name()).into_bytes()
    } else {
        format!("{}-secret:{name}", app.name()).into_bytes()
    }
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("The random source failed: {e}"))?;
    Ok(bytes)
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&Key::from(*key))
}

fn nonce(bytes: &[u8]) -> XNonce {
    XNonce::from(<[u8; 24]>::try_from(bytes).expect("validated on load"))
}

mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests;
