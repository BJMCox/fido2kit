mod crypto;
mod file;

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail, ensure};
use zeroize::Zeroizing;

use crate::App;
pub use crate::fido::{Enrollment, Unlock};
use crypto::Encoder;

const VERSION: u32 = 3;
/// A vault with a few keys and passwords is a few kilobytes. The bound keeps parsing fast.
const MAX_VAULT_BYTES: u64 = 1 << 20;
const META_ENTRIES: usize = 64;
const META_VALUE_BYTES: usize = 1024;
/// Shamir x-coordinates are bytes, so a split has at most 255 shares.
const MAX_SHARES: usize = 255;

/// The name that matches any lookup without its own entry.
pub const ANY: &str = "*";

/// The result of checking keys: their labels, and the secrets they open or not.
pub struct Check {
    pub labels: Vec<String>,
    pub opened: Vec<String>,
    /// Only a v1 or v2 vault can list a secret here, because v3 checks every byte with its tag.
    pub failed: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// Wraps under a key derived from the hmac-secret output.
    Fido2Hmac,
    /// Carried over from a v2 vault: wraps under the hmac-secret output itself. It becomes
    /// [`KeyKind::Fido2Hmac`] the next time its key takes part in a change.
    Fido2HmacV2,
}

impl KeyKind {
    fn name(self) -> &'static str {
        match self {
            Self::Fido2Hmac => "fido2-hmac",
            Self::Fido2HmacV2 => "fido2-hmac-v2",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        [Self::Fido2Hmac, Self::Fido2HmacV2]
            .into_iter()
            .find(|kind| kind.name() == name)
    }
}

/// An enrolled key as the file describes it. Unverified until an unwrap checks the tag.
pub struct KeyInfo<'a> {
    pub label: &'a str,
    pub cred_id: &'a [u8],
    pub kind: KeyKind,
    pub aaguid: Option<[u8; 16]>,
    /// UNIX seconds at enrollment.
    pub created: Option<u64>,
    /// Whether the key was enrolled with its PIN.
    pub uv: Option<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    /// Loaded from v1 or v2 and not changed since, so it saves as v2 with its old bytes.
    Legacy,
    V3,
}

/// Builds only through [`Vault::create`] and the private parser, so every vault passes
/// validation.
#[derive(Clone)]
pub struct Vault {
    format: Format,
    threshold: u8,
    generation: u64,
    meta: BTreeMap<String, String>,
    keys: Vec<KeyEntry>,
    secrets: Vec<SecretEntry>,
    /// Zero until a legacy vault first changes.
    tag: [u8; 32],
    /// The file text this vault was loaded from or last saved as. A save refuses to replace a
    /// file that no longer holds it.
    loaded: Option<String>,
    /// Names the key schedule, the AAD, the temp files, and the messages.
    app: App,
}

#[derive(Clone)]
struct KeyEntry {
    kind: KeyKind,
    label: String,
    cred_id: Vec<u8>,
    /// Every entry holds the same salt. One CTAP2 assertion carries one hmac-secret salt for its
    /// whole credential list, so per-key salts would need a lookup of the key's credential before
    /// each unlock. The field lets a later version change that without a new format.
    salt: [u8; 32],
    /// 0 when the threshold is 1, else the Shamir x-coordinate.
    share: u8,
    nonce: [u8; 24],
    wrapped: Vec<u8>,
    aaguid: Option<[u8; 16]>,
    created: Option<u64>,
    uv: Option<bool>,
    meta: BTreeMap<String, String>,
}

#[derive(Clone)]
struct Sealed {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

/// One stored secret. `name` is what the app looks it up by, such as fido2kpxc's `pdb.kdbx`,
/// or [`ANY`].
#[derive(Clone)]
struct SecretEntry {
    name: String,
    current: Sealed,
    pending: Option<Sealed>,
    meta: BTreeMap<String, String>,
}

impl Vault {
    pub fn new_salt() -> Result<[u8; 32]> {
        crypto::random()
    }

    pub fn create(
        app: App,
        salt: [u8; 32],
        label: &str,
        enrollment: &Enrollment,
        name: &str,
        secret: &[u8],
    ) -> Result<Self> {
        let key = Zeroizing::new(crypto::random::<32>()?);
        let mut entry = KeyEntry::new(label, enrollment, salt);
        wrap(app, 1, &mut entry, &enrollment.unlock, &key)?;
        let mut vault = Self {
            format: Format::V3,
            threshold: 1,
            generation: 1,
            meta: BTreeMap::new(),
            keys: vec![entry],
            secrets: vec![SecretEntry {
                name: name.to_owned(),
                current: seal(app, &key, name, false, secret)?,
                pending: None,
                meta: BTreeMap::new(),
            }],
            tag: [0; 32],
            loaded: None,
            app,
        };
        vault.tag = vault.compute_tag(&key);
        vault.validate()?;
        Ok(vault)
    }

    /// Loads a v3 vault. v1 and v2 files have no tag, so someone could put one back over a v3
    /// vault, and this refuses them.
    pub fn load(app: App, path: &Path) -> Result<Self> {
        Self::load_from(app, path, false)
    }

    /// Also loads v1 and v2 vaults, for an app that has them in use. Their first change writes
    /// v3.
    pub fn load_legacy(app: App, path: &Path) -> Result<Self> {
        Self::load_from(app, path, true)
    }

    fn load_from(app: App, path: &Path, legacy: bool) -> Result<Self> {
        let text = read_vault(path)?;
        let mut vault = Self::parse(app, &text, legacy)
            .with_context(|| format!("Invalid vault {}", path.display()))?;
        vault.loaded = Some(text);
        Ok(vault)
    }

    /// 3, or 2 for a v1 or v2 vault that has not changed since it loaded.
    pub fn version(&self) -> u32 {
        match self.format {
            Format::Legacy => 2,
            Format::V3 => VERSION,
        }
    }

    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn salt(&self) -> [u8; 32] {
        self.keys[0].salt
    }

    pub fn cred_ids(&self) -> Vec<&[u8]> {
        self.keys.iter().map(|k| k.cred_id.as_slice()).collect()
    }

    /// The enrolled keys, in vault order. Unverified until an unwrap checks the tag.
    pub fn keys(&self) -> Vec<KeyInfo<'_>> {
        self.keys
            .iter()
            .map(|k| KeyInfo {
                label: &k.label,
                cred_id: &k.cred_id,
                kind: k.kind,
                aaguid: k.aaguid,
                created: k.created,
                uv: k.uv,
            })
            .collect()
    }

    /// Stored secret names, in vault order.
    pub fn names(&self) -> Vec<&str> {
        self.secrets.iter().map(|s| s.name.as_str()).collect()
    }

    /// Unverified until an unwrap checks the tag.
    pub fn meta(&self) -> &BTreeMap<String, String> {
        &self.meta
    }

    /// Unverified until an unwrap checks the tag.
    pub fn secret_meta(&self, name: &str) -> Option<&BTreeMap<String, String>> {
        self.secret(name).ok().map(|s| &s.meta)
    }

    pub fn has_pending(&self, name: &str) -> bool {
        self.secret(name).is_ok_and(|s| s.pending.is_some())
    }

    /// True when `open` would find a password for `name`.
    pub fn has_secret_for(&self, name: Option<&str>) -> bool {
        self.secret_for(name).is_some()
    }

    /// The labels and credential IDs of the keys that stay after removing `labels`. Fails on an
    /// unknown label, or if no key would stay. Unverified until an unwrap checks the tag.
    pub fn kept_keys(&self, labels: &[&str]) -> Result<Vec<(&str, &[u8])>> {
        for label in labels {
            ensure!(
                self.keys.iter().any(|k| k.label == *label),
                "No key is labeled {label:?}"
            );
        }
        let kept: Vec<(&str, &[u8])> = self
            .keys
            .iter()
            .filter(|k| !labels.contains(&k.label.as_str()))
            .map(|k| (k.label.as_str(), k.cred_id.as_slice()))
            .collect();
        ensure!(!kept.is_empty(), "At least one key must stay enrolled");
        Ok(kept)
    }

    /// Decrypts the password for `name`: its own entry if one exists, else the [`ANY`] entry.
    pub fn open(&self, unlocks: &[Unlock], name: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
        let key = self.data_key(&refs(unlocks))?;
        let Some(entry) = self.secret_for(name) else {
            return Err(match name {
                Some(name) => anyhow!("No password is stored for {name}"),
                None => anyhow!("No password is stored"),
            });
        };
        self.decrypt(&key, entry, false)
    }

    /// The pending value of `name`, if it has one.
    pub fn open_pending(
        &self,
        unlocks: &[Unlock],
        name: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let key = self.data_key(&refs(unlocks))?;
        let entry = self.secret(name)?;
        entry
            .pending
            .is_some()
            .then(|| self.decrypt(&key, entry, true))
            .transpose()
    }

    /// Unwraps with `unlocks` and checks the tag, without returning a secret.
    pub fn verify(&self, unlocks: &[Unlock]) -> Result<()> {
        self.data_key(&refs(unlocks)).map(drop)
    }

    /// Which enrolled keys `unlocks` belong to, and which stored passwords they decrypt.
    pub fn check(&self, unlocks: &[Unlock]) -> Result<Check> {
        let unlocks = refs(unlocks);
        let labels = unlocks
            .iter()
            .map(|unlock| {
                let entry = self.entry(unlock)?;
                self.unwrap(entry, unlock)?;
                Ok(entry.label.clone())
            })
            .collect::<Result<_>>()?;
        let key = self.data_key(&unlocks)?;
        let (mut opened, mut failed) = (Vec::new(), Vec::new());
        for entry in &self.secrets {
            match self.decrypt(&key, entry, false) {
                Ok(_) => opened.push(entry.name.clone()),
                Err(_) => failed.push(entry.name.clone()),
            }
        }
        Ok(Check {
            labels,
            opened,
            failed,
        })
    }

    /// Enrolls `new`. With a threshold above 1 the data key is split again, so every enrolled
    /// key must be in `unlocks`.
    pub fn add_key(&mut self, unlocks: &[Unlock], label: &str, new: &Enrollment) -> Result<()> {
        // The tag check comes first, so a changed file reports itself, not a side effect.
        self.data_key(&refs(unlocks))?;
        ensure!(
            self.keys.iter().all(|k| k.label != label),
            "Label {label:?} already exists"
        );
        ensure!(
            self.keys.iter().all(|k| k.cred_id != new.unlock.cred_id),
            "This security key is already enrolled"
        );
        let unlocks = refs(unlocks);
        let present = if self.threshold == 1 {
            Vec::new()
        } else {
            self.every_key(&unlocks)?
        };
        self.change(&unlocks, |vault, key| {
            vault.keys.push(KeyEntry::new(label, new, vault.salt()));
            if vault.threshold == 1 {
                let entry = vault.keys.last_mut().expect("just pushed");
                wrap(vault.app, 1, entry, &new.unlock, &key)?;
            } else {
                let mut outputs = present;
                outputs.push(&new.unlock);
                vault.wrap_all(&key, &outputs, vault.threshold)?;
            }
            Ok(key)
        })
    }

    /// Drops the keys in `labels` and moves every secret to a new data key. A removed key that
    /// kept an old vault copy knows the old data key, so every kept key must be in `unlocks` to
    /// wrap the new one.
    pub fn remove_keys(&mut self, labels: &[&str], unlocks: &[Unlock]) -> Result<()> {
        // The tag check comes first, so a swapped label reports a changed file, not a missing key.
        self.data_key(&refs(unlocks))?;
        let kept = self.kept_keys(labels)?;
        ensure!(
            kept.len() >= usize::from(self.threshold),
            "At least {} keys must stay enrolled",
            self.threshold
        );
        let kept: Vec<&Unlock> = kept
            .iter()
            .map(|(label, cred_id)| {
                unlocks
                    .iter()
                    .find(|u| u.cred_id == *cred_id)
                    .with_context(|| format!("Key {label:?} must be present"))
            })
            .collect::<Result<_>>()?;
        self.change(&kept, |vault, old_key| {
            let plain = vault
                .secrets
                .iter()
                .map(|s| {
                    let pending = s
                        .pending
                        .is_some()
                        .then(|| vault.decrypt(&old_key, s, true));
                    Ok((vault.decrypt(&old_key, s, false)?, pending.transpose()?))
                })
                .collect::<Result<Vec<_>>>()?;
            let key = Zeroizing::new(crypto::random::<32>()?);
            for (secret, (current, pending)) in vault.secrets.iter_mut().zip(&plain) {
                secret.current = seal(vault.app, &key, &secret.name, false, current)?;
                secret.pending = pending
                    .as_ref()
                    .map(|p| seal(vault.app, &key, &secret.name, true, p))
                    .transpose()?;
            }
            vault
                .keys
                .retain(|k| kept.iter().any(|u| u.cred_id == k.cred_id));
            let outputs = vault.every_key(&kept)?;
            vault.wrap_all(&key, &outputs, vault.threshold)?;
            Ok(key)
        })
    }

    /// Sets how many keys an unwrap needs. Every enrolled key must be in `unlocks`, because each
    /// one wraps a new share.
    pub fn set_threshold(&mut self, unlocks: &[Unlock], k: u8) -> Result<()> {
        self.data_key(&refs(unlocks))?;
        ensure!(
            k >= 1 && usize::from(k) <= self.keys.len(),
            "The threshold must be between 1 and the number of keys"
        );
        let unlocks = refs(unlocks);
        let present = self.every_key(&unlocks)?;
        self.change(&unlocks, |vault, key| {
            vault.wrap_all(&key, &present, k)?;
            Ok(key)
        })
    }

    /// Adds or replaces the password for `name`. A replaced entry keeps its pending value and
    /// meta.
    pub fn set_secret(&mut self, unlocks: &[Unlock], name: &str, secret: &[u8]) -> Result<()> {
        self.change(&refs(unlocks), |vault, key| {
            let current = seal(vault.app, &key, name, false, secret)?;
            match vault.secrets.iter_mut().find(|s| s.name == name) {
                Some(entry) => entry.current = current,
                None => vault.secrets.push(SecretEntry {
                    name: name.to_owned(),
                    current,
                    pending: None,
                    meta: BTreeMap::new(),
                }),
            }
            Ok(key)
        })
    }

    pub fn remove_secret(&mut self, unlocks: &[Unlock], name: &str) -> Result<()> {
        self.secret(name)?;
        ensure!(
            self.secrets.len() > 1,
            "The vault must keep at least one password"
        );
        self.change(&refs(unlocks), |vault, key| {
            vault.secrets.retain(|s| s.name != name);
            Ok(key)
        })
    }

    /// Stores a pending value for `name` beside its current one. With [`Vault::commit_pending`]
    /// and [`Vault::discard_pending`], an app can change a secret outside the vault so that a
    /// crash at any step leaves a vault that still opens.
    pub fn set_pending(&mut self, unlocks: &[Unlock], name: &str, secret: &[u8]) -> Result<()> {
        self.secret(name)?;
        self.change(&refs(unlocks), |vault, key| {
            let pending = seal(vault.app, &key, name, true, secret)?;
            vault.secret_mut(name).pending = Some(pending);
            Ok(key)
        })
    }

    /// Makes the pending value of `name` its current one.
    pub fn commit_pending(&mut self, unlocks: &[Unlock], name: &str) -> Result<()> {
        self.pending_of(name)?;
        self.change(&refs(unlocks), |vault, key| {
            let value = vault.decrypt(&key, vault.secret(name)?, true)?;
            let current = seal(vault.app, &key, name, false, &value)?;
            let entry = vault.secret_mut(name);
            entry.current = current;
            entry.pending = None;
            Ok(key)
        })
    }

    pub fn discard_pending(&mut self, unlocks: &[Unlock], name: &str) -> Result<()> {
        self.pending_of(name)?;
        self.change(&refs(unlocks), |vault, key| {
            vault.secret_mut(name).pending = None;
            Ok(key)
        })
    }

    pub fn set_meta(&mut self, unlocks: &[Unlock], key: &str, value: &str) -> Result<()> {
        check_meta_entry(key, value)?;
        self.change(&refs(unlocks), |vault, data_key| {
            vault.meta.insert(key.to_owned(), value.to_owned());
            Ok(data_key)
        })
    }

    pub fn set_secret_meta(
        &mut self,
        unlocks: &[Unlock],
        name: &str,
        key: &str,
        value: &str,
    ) -> Result<()> {
        self.secret(name)?;
        check_meta_entry(key, value)?;
        self.change(&refs(unlocks), |vault, data_key| {
            vault
                .secret_mut(name)
                .meta
                .insert(key.to_owned(), value.to_owned());
            Ok(data_key)
        })
    }

    /// Writes v3 with no other change, and moves the present keys' migrated entries to v3
    /// wrapping.
    pub fn upgrade(&mut self, unlocks: &[Unlock]) -> Result<()> {
        self.change(&refs(unlocks), |_, key| Ok(key))
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
        // comparison below still refuses a stale write there. The raw numbers are macOS values,
        // so they match only there.
        if let Err(e) = lock.lock()
            && e.kind() != std::io::ErrorKind::Unsupported
            && !(cfg!(target_os = "macos") && matches!(e.raw_os_error(), Some(45 | 102)))
        {
            return Err(e).with_context(|| format!("Cannot lock {}", dir.display()));
        }
        if !create {
            ensure!(
                read_vault(path).ok() == self.loaded,
                "The vault changed while this ran, for example from another window or computer. Nothing was saved. Try again."
            );
        }
        let text = self.to_text()?;
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

    /// Unwraps with `unlocks`, checks the tag, applies `edit` to a copy, and keeps the copy only
    /// when every step succeeds. A legacy vault becomes v3 first. `edit` returns the data key the
    /// result is tagged with.
    fn change(
        &mut self,
        unlocks: &[&Unlock],
        edit: impl FnOnce(&mut Self, Zeroizing<[u8; 32]>) -> Result<Zeroizing<[u8; 32]>>,
    ) -> Result<()> {
        let key = self.data_key(unlocks)?;
        // A change may rewrap any entry whose unlock it was given, so each output first proves
        // itself against its current wrapping. A wrong one would lock its key out for good.
        for unlock in unlocks {
            self.unwrap(self.entry(unlock)?, unlock)?;
        }
        let mut next = self.clone();
        next.migrate(&key, unlocks)?;
        let key = edit(&mut next, key)?;
        next.generation += 1;
        next.tag = next.compute_tag(&key);
        next.validate()?;
        *self = next;
        Ok(())
    }

    fn migrate(&mut self, key: &[u8; 32], unlocks: &[&Unlock]) -> Result<()> {
        if self.format == Format::Legacy {
            let plain = self
                .secrets
                .iter()
                .map(|s| self.decrypt(key, s, false))
                .collect::<Result<Vec<_>>>()?;
            self.format = Format::V3;
            self.threshold = 1;
            self.generation = 0;
            for (secret, value) in self.secrets.iter_mut().zip(&plain) {
                secret.current = seal(self.app, key, &secret.name, false, value)?;
            }
        }
        for unlock in unlocks {
            let (app, threshold) = (self.app, self.threshold);
            if let Some(entry) = self
                .keys
                .iter_mut()
                .find(|k| k.cred_id == unlock.cred_id && k.kind == KeyKind::Fido2HmacV2)
            {
                // Migrated entries exist only with a threshold of 1, so they wrap the data key.
                wrap(app, threshold, entry, unlock, key)?;
            }
        }
        Ok(())
    }

    /// Wraps `key`, or with `k` above 1 a new split of it, for every entry. `outputs` holds each
    /// entry's unlock in entry order.
    fn wrap_all(&mut self, key: &[u8; 32], outputs: &[&Unlock], k: u8) -> Result<()> {
        let n = self.keys.len();
        let values = if k == 1 {
            vec![Zeroizing::new(*key); n]
        } else {
            ensure!(
                n <= MAX_SHARES,
                "A vault with a threshold holds at most 255 keys"
            );
            crypto::split(key, k, n)?
        };
        self.threshold = k;
        for (index, (entry, (unlock, value))) in self
            .keys
            .iter_mut()
            .zip(outputs.iter().zip(&values))
            .enumerate()
        {
            entry.share = if k == 1 {
                0
            } else {
                u8::try_from(index + 1).expect("at most 255 shares")
            };
            wrap(self.app, k, entry, unlock, value)?;
        }
        Ok(())
    }

    /// The unlock for each entry, in entry order.
    fn every_key<'a>(&self, unlocks: &[&'a Unlock]) -> Result<Vec<&'a Unlock>> {
        self.keys
            .iter()
            .map(|entry| {
                unlocks
                    .iter()
                    .copied()
                    .find(|u| u.cred_id == entry.cred_id)
                    .with_context(|| format!("Key {:?} must be present", entry.label))
            })
            .collect()
    }

    /// Unwraps enough keys to rebuild the data key, then checks the tag with it before anything
    /// else uses it.
    fn data_key(&self, unlocks: &[&Unlock]) -> Result<Zeroizing<[u8; 32]>> {
        let needed = usize::from(self.threshold);
        let mut seen = HashSet::new();
        let mut shares: Vec<(u8, Zeroizing<[u8; 32]>)> = Vec::new();
        for unlock in unlocks {
            if shares.len() == needed {
                break;
            }
            let entry = self.entry(unlock)?;
            if seen.insert(entry.cred_id.as_slice()) {
                shares.push((entry.share, self.unwrap(entry, unlock)?));
            }
        }
        ensure!(
            shares.len() == needed,
            "This vault needs {needed} of its security keys, and {} were given",
            shares.len()
        );
        let key = if needed == 1 {
            shares.pop().expect("one share").1
        } else {
            let points: Vec<(u8, &[u8; 32])> = shares.iter().map(|(x, y)| (*x, &**y)).collect();
            crypto::combine(&points)?
        };
        if self.format == Format::V3 {
            ensure!(
                crypto::tag_matches(self.app, &key, &self.encoding(), &self.tag),
                "The vault was changed outside {} or is damaged. Nothing was changed.",
                self.app.name()
            );
        }
        Ok(key)
    }

    fn entry(&self, unlock: &Unlock) -> Result<&KeyEntry> {
        self.keys
            .iter()
            .find(|k| k.cred_id == unlock.cred_id)
            .context("This security key is not enrolled in the vault")
    }

    fn unwrap(&self, entry: &KeyEntry, unlock: &Unlock) -> Result<Zeroizing<[u8; 32]>> {
        let plain = match entry.kind {
            KeyKind::Fido2Hmac => crypto::open(
                &crypto::wrap_key(self.app, &unlock.output, &entry.salt, &entry.cred_id),
                &entry.nonce,
                &key_aad(self.app, self.threshold, &entry.cred_id, entry.share),
                &entry.wrapped,
            ),
            KeyKind::Fido2HmacV2 => {
                crypto::open(&unlock.output, &entry.nonce, &entry.cred_id, &entry.wrapped)
            }
        }
        .ok_or_else(|| match self.format {
            Format::Legacy => anyhow!("Key entry {:?} failed authentication", entry.label),
            // Without the data key the tag cannot be checked, so both causes stay possible.
            Format::V3 => anyhow!(
                "Key entry {:?} failed authentication. The vault was changed outside {} or is damaged, or this key answered differently than at enrollment. Nothing was changed.",
                entry.label,
                self.app.name()
            ),
        })?;
        let value: [u8; 32] = plain
            .as_slice()
            .try_into()
            .context("The wrapped key has the wrong length")?;
        Ok(Zeroizing::new(value))
    }

    fn decrypt(
        &self,
        key: &[u8; 32],
        entry: &SecretEntry,
        pending: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let sealed = if pending {
            entry
                .pending
                .as_ref()
                .with_context(|| format!("No pending value is stored for {:?}", entry.name))?
        } else {
            &entry.current
        };
        match self.format {
            Format::Legacy => crypto::open(
                key,
                &sealed.nonce,
                &legacy_secret_aad(self.app, &entry.name),
                &sealed.ciphertext,
            ),
            Format::V3 => crypto::open(
                &crypto::secret_key(self.app, key),
                &sealed.nonce,
                &secret_aad(self.app, &entry.name, pending),
                &sealed.ciphertext,
            ),
        }
        .ok_or_else(|| anyhow!("The password for {:?} failed authentication", entry.name))
    }

    fn secret_for(&self, name: Option<&str>) -> Option<&SecretEntry> {
        let exact = name.and_then(|name| self.secrets.iter().find(|s| s.name == name));
        exact.or_else(|| self.secrets.iter().find(|s| s.name == ANY))
    }

    fn secret(&self, name: &str) -> Result<&SecretEntry> {
        self.secrets
            .iter()
            .find(|s| s.name == name)
            .with_context(|| format!("No password is stored for {name:?}"))
    }

    /// Only for names that `secret` found before the change began.
    fn secret_mut(&mut self, name: &str) -> &mut SecretEntry {
        self.secrets
            .iter_mut()
            .find(|s| s.name == name)
            .expect("checked before the change")
    }

    fn pending_of(&self, name: &str) -> Result<()> {
        ensure!(
            self.secret(name)?.pending.is_some(),
            "No pending value is stored for {name:?}"
        );
        Ok(())
    }

    fn compute_tag(&self, key: &[u8; 32]) -> [u8; 32] {
        crypto::tag(self.app, key, &self.encoding())
    }

    /// Everything in the file but the tag, in file order.
    fn encoding(&self) -> Vec<u8> {
        let mut e = Encoder::default();
        e.bytes("fido2kit/v3/vault")
            .bytes(self.app.name())
            .int(u64::from(VERSION))
            .bytes(crypto::AEAD)
            .bytes(crypto::KDF)
            .bytes(crypto::MAC)
            .int(u64::from(self.threshold))
            .int(self.generation)
            .map(&self.meta)
            .int(self.keys.len() as u64);
        for key in &self.keys {
            e.bytes(key.kind.name())
                .bytes(&key.label)
                .bytes(&key.cred_id)
                .bytes(key.salt)
                .int(u64::from(key.share))
                .bytes(key.nonce)
                .bytes(&key.wrapped);
            match key.aaguid {
                Some(aaguid) => e.flag(true).bytes(aaguid),
                None => e.flag(false),
            };
            match key.created {
                Some(created) => e.flag(true).int(created),
                None => e.flag(false),
            };
            match key.uv {
                Some(uv) => e.flag(true).flag(uv),
                None => e.flag(false),
            };
            e.map(&key.meta);
        }
        e.int(self.secrets.len() as u64);
        for secret in &self.secrets {
            e.bytes(&secret.name)
                .bytes(secret.current.nonce)
                .bytes(&secret.current.ciphertext);
            match &secret.pending {
                Some(p) => e.flag(true).bytes(p.nonce).bytes(&p.ciphertext),
                None => e.flag(false),
            };
            e.map(&secret.meta);
        }
        e.finish()
    }

    fn to_text(&self) -> Result<String> {
        Ok(match self.format {
            Format::Legacy => toml::to_string(&file::V2 {
                version: 2,
                salt: self.salt().to_vec(),
                keys: self
                    .keys
                    .iter()
                    .map(|k| file::KeyV2 {
                        label: k.label.clone(),
                        cred_id: k.cred_id.clone(),
                        nonce: k.nonce.to_vec(),
                        wrapped_key: k.wrapped.clone(),
                    })
                    .collect(),
                secrets: self
                    .secrets
                    .iter()
                    .map(|s| file::SecretV2 {
                        name: s.name.clone(),
                        nonce: s.current.nonce.to_vec(),
                        ciphertext: s.current.ciphertext.clone(),
                    })
                    .collect(),
            })?,
            Format::V3 => toml::to_string(&file::V3 {
                version: VERSION,
                aead: crypto::AEAD.to_owned(),
                kdf: crypto::KDF.to_owned(),
                mac: crypto::MAC.to_owned(),
                threshold: self.threshold,
                generation: self.generation,
                tag: self.tag.to_vec(),
                meta: self.meta.clone(),
                keys: self
                    .keys
                    .iter()
                    .map(|k| file::KeyV3 {
                        kind: k.kind.name().to_owned(),
                        label: k.label.clone(),
                        cred_id: k.cred_id.clone(),
                        salt: k.salt.to_vec(),
                        share: k.share,
                        nonce: k.nonce.to_vec(),
                        wrapped: k.wrapped.clone(),
                        aaguid: k.aaguid.map(|a| a.to_vec()),
                        created: k.created,
                        uv: k.uv,
                        meta: k.meta.clone(),
                    })
                    .collect(),
                secrets: self
                    .secrets
                    .iter()
                    .map(|s| file::SecretV3 {
                        name: s.name.clone(),
                        nonce: s.current.nonce.to_vec(),
                        ciphertext: s.current.ciphertext.clone(),
                        pending_nonce: s.pending.as_ref().map(|p| p.nonce.to_vec()),
                        pending_ciphertext: s.pending.as_ref().map(|p| p.ciphertext.clone()),
                        meta: s.meta.clone(),
                    })
                    .collect(),
            })?,
        })
    }

    fn parse(app: App, text: &str, legacy: bool) -> Result<Self> {
        let version = toml::from_str::<toml::Table>(text)?
            .get("version")
            .and_then(toml::Value::as_integer)
            .context("The vault has no version")?;
        let vault = match version {
            // A v1 or v2 file here is either a vault that was never migrated or an old copy put back
            // over a v3 one, and migrating the copy would restore keys removed since.
            1 | 2 if !legacy => bail!(
                "This vault has an older format without a tag, which {app} no longer reads. If it used the current format before, an older copy replaced it: restore your current copy, because migrating this one brings back keys removed since. Otherwise, open it once with an earlier {app} release that migrates it.",
                app = app.name()
            ),
            1 => {
                let v1: file::V1 = toml::from_str(text)?;
                let salt = bytes::<32>(v1.salt, "salt")?;
                Self::legacy(
                    app,
                    salt,
                    v1.keys,
                    vec![file::SecretV2 {
                        name: ANY.to_owned(),
                        nonce: v1.nonce,
                        ciphertext: v1.ciphertext,
                    }],
                )?
            }
            2 => {
                let v2: file::V2 = toml::from_str(text)?;
                let salt = bytes::<32>(v2.salt, "salt")?;
                Self::legacy(app, salt, v2.keys, v2.secrets)?
            }
            3 => Self::from_v3(app, toml::from_str(text)?)?,
            other => bail!(
                "The vault has version {other}, from a newer {app}. Update {app}.",
                app = app.name()
            ),
        };
        vault.validate()?;
        Ok(vault)
    }

    fn legacy(
        app: App,
        salt: [u8; 32],
        keys: Vec<file::KeyV2>,
        secrets: Vec<file::SecretV2>,
    ) -> Result<Self> {
        Ok(Self {
            format: Format::Legacy,
            threshold: 1,
            generation: 0,
            meta: BTreeMap::new(),
            keys: keys
                .into_iter()
                .map(|k| {
                    Ok(KeyEntry {
                        kind: KeyKind::Fido2HmacV2,
                        label: k.label,
                        cred_id: k.cred_id,
                        salt,
                        share: 0,
                        nonce: bytes(k.nonce, "key nonce")?,
                        wrapped: k.wrapped_key,
                        aaguid: None,
                        created: None,
                        uv: None,
                        meta: BTreeMap::new(),
                    })
                })
                .collect::<Result<_>>()?,
            secrets: secrets
                .into_iter()
                .map(|s| {
                    Ok(SecretEntry {
                        name: s.name,
                        current: Sealed {
                            nonce: bytes(s.nonce, "secret nonce")?,
                            ciphertext: s.ciphertext,
                        },
                        pending: None,
                        meta: BTreeMap::new(),
                    })
                })
                .collect::<Result<_>>()?,
            tag: [0; 32],
            loaded: None,
            app,
        })
    }

    fn from_v3(app: App, file: file::V3) -> Result<Self> {
        let newer = |what: &str| {
            anyhow!(
                "The vault uses {what}, which needs a newer {app}. Update {app}.",
                app = app.name()
            )
        };
        for (name, known) in [
            (&file.aead, crypto::AEAD),
            (&file.kdf, crypto::KDF),
            (&file.mac, crypto::MAC),
        ] {
            if name != known {
                return Err(newer(name));
            }
        }
        Ok(Self {
            format: Format::V3,
            threshold: file.threshold,
            generation: file.generation,
            meta: file.meta,
            keys: file
                .keys
                .into_iter()
                .map(|k| {
                    Ok(KeyEntry {
                        kind: KeyKind::from_name(&k.kind).ok_or_else(|| newer(&k.kind))?,
                        label: k.label,
                        cred_id: k.cred_id,
                        salt: bytes(k.salt, "key salt")?,
                        share: k.share,
                        nonce: bytes(k.nonce, "key nonce")?,
                        wrapped: k.wrapped,
                        aaguid: k.aaguid.map(|a| bytes(a, "AAGUID")).transpose()?,
                        created: k.created,
                        uv: k.uv,
                        meta: k.meta,
                    })
                })
                .collect::<Result<_>>()?,
            secrets: file
                .secrets
                .into_iter()
                .map(|s| {
                    let pending = match (s.pending_nonce, s.pending_ciphertext) {
                        (None, None) => None,
                        (Some(nonce), Some(ciphertext)) => Some(Sealed {
                            nonce: bytes(nonce, "pending nonce")?,
                            ciphertext,
                        }),
                        _ => bail!("The pending value of {:?} is incomplete", s.name),
                    };
                    Ok(SecretEntry {
                        current: Sealed {
                            nonce: bytes(s.nonce, "secret nonce")?,
                            ciphertext: s.ciphertext,
                        },
                        name: s.name,
                        pending,
                        meta: s.meta,
                    })
                })
                .collect::<Result<_>>()?,
            tag: bytes(file.tag, "tag")?,
            loaded: None,
            app,
        })
    }

    fn validate(&self) -> Result<()> {
        ensure!(!self.keys.is_empty(), "The vault has no enrolled keys");
        ensure!(!self.secrets.is_empty(), "The vault holds no password");
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
        ensure!(
            self.keys.iter().all(|k| k.salt == self.keys[0].salt),
            "The vault's keys have different salts, which needs a newer {app}. Update {app}.",
            app = self.app.name()
        );
        let n = self.keys.len();
        ensure!(
            self.threshold >= 1 && usize::from(self.threshold) <= n,
            "The vault's threshold must be between 1 and its number of keys"
        );
        if self.threshold == 1 {
            ensure!(
                self.keys.iter().all(|k| k.share == 0),
                "The vault has a key share but a threshold of 1"
            );
        } else {
            ensure!(
                n <= MAX_SHARES,
                "A vault with a threshold holds at most 255 keys"
            );
            let mut shares = HashSet::new();
            ensure!(
                self.keys
                    .iter()
                    .all(|k| k.share != 0 && shares.insert(k.share)),
                "The vault's key shares must be distinct and nonzero"
            );
            ensure!(
                self.keys.iter().all(|k| k.kind == KeyKind::Fido2Hmac),
                "A migrated key entry cannot hold a share"
            );
        }
        let maps = std::iter::once(&self.meta)
            .chain(self.keys.iter().map(|k| &k.meta))
            .chain(self.secrets.iter().map(|s| &s.meta));
        for map in maps {
            ensure!(
                map.len() <= META_ENTRIES,
                "A metadata map holds more than {META_ENTRIES} entries"
            );
            for (key, value) in map {
                check_meta_entry(key, value)?;
            }
        }
        Ok(())
    }
}

impl KeyEntry {
    /// An entry for `enrollment`, not yet wrapped.
    fn new(label: &str, enrollment: &Enrollment, salt: [u8; 32]) -> Self {
        Self {
            kind: KeyKind::Fido2Hmac,
            label: label.to_owned(),
            cred_id: enrollment.unlock.cred_id.clone(),
            salt,
            share: 0,
            nonce: [0; 24],
            wrapped: Vec::new(),
            aaguid: Some(enrollment.aaguid),
            created: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
            uv: Some(enrollment.uv),
            meta: BTreeMap::new(),
        }
    }
}

/// Wraps `value` for `unlock` into `entry` as a v3 entry.
fn wrap(
    app: App,
    threshold: u8,
    entry: &mut KeyEntry,
    unlock: &Unlock,
    value: &[u8; 32],
) -> Result<()> {
    let kek = crypto::wrap_key(app, &unlock.output, &entry.salt, &entry.cred_id);
    let aad = key_aad(app, threshold, &entry.cred_id, entry.share);
    let (nonce, wrapped) = crypto::seal(&kek, &aad, value)?;
    entry.kind = KeyKind::Fido2Hmac;
    entry.nonce = nonce;
    entry.wrapped = wrapped;
    Ok(())
}

fn seal(app: App, key: &[u8; 32], name: &str, pending: bool, value: &[u8]) -> Result<Sealed> {
    let (nonce, ciphertext) = crypto::seal(
        &crypto::secret_key(app, key),
        &secret_aad(app, name, pending),
        value,
    )?;
    Ok(Sealed { nonce, ciphertext })
}

/// Binds a wrapped value to its key, threshold, and share, so it cannot move between entries.
fn key_aad(app: App, threshold: u8, cred_id: &[u8], share: u8) -> Vec<u8> {
    Encoder::default()
        .bytes("fido2kit/v3/key")
        .bytes(app.name())
        .bytes(cred_id)
        .int(u64::from(threshold))
        .int(u64::from(share))
        .finish()
}

/// Binds a secret to its app, name, and state, so a pending value cannot pass as the current one.
fn secret_aad(app: App, name: &str, pending: bool) -> Vec<u8> {
    Encoder::default()
        .bytes("fido2kit/v3/secret")
        .bytes(app.name())
        .bytes(name)
        .bytes(if pending { "pending" } else { "current" })
        .finish()
}

/// The v1 and v2 binding of each password to its app and name. The [`ANY`] entry keeps the
/// version 1 value, so migrated v1 vaults needed no re-encryption. For fido2kpxc both values are
/// the bytes it always used.
fn legacy_secret_aad(app: App, name: &str) -> Vec<u8> {
    if name == ANY {
        format!("{}-vault-v1", app.name()).into_bytes()
    } else {
        format!("{}-secret:{name}", app.name()).into_bytes()
    }
}

fn check_meta_entry(key: &str, value: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&key.len())
            && key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)),
        "The metadata key {key:?} must be 1 to 64 characters of a-z, 0-9, '.', '_', or '-'"
    );
    ensure!(
        value.len() <= META_VALUE_BYTES,
        "The metadata value for {key:?} is longer than {META_VALUE_BYTES} bytes"
    );
    Ok(())
}

fn bytes<const N: usize>(value: Vec<u8>, what: &str) -> Result<[u8; N]> {
    value
        .try_into()
        .map_err(|_| anyhow!("The vault's {what} has the wrong length"))
}

/// Reads at most 1 MiB and one byte, from a regular file only, so a FIFO or a link to a device
/// cannot hang or exhaust the app.
fn read_vault(path: &Path) -> Result<String> {
    let cannot = || format!("Cannot read vault {}", path.display());
    let metadata = std::fs::metadata(path).with_context(cannot)?;
    ensure!(
        metadata.is_file(),
        "The vault {} is not a regular file",
        path.display()
    );
    let mut text = String::new();
    std::fs::File::open(path)
        .with_context(cannot)?
        .take(MAX_VAULT_BYTES + 1)
        .read_to_string(&mut text)
        .with_context(cannot)?;
    ensure!(
        text.len() as u64 <= MAX_VAULT_BYTES,
        "The vault {} is larger than 1 MiB",
        path.display()
    );
    Ok(text)
}

fn refs(unlocks: &[Unlock]) -> Vec<&Unlock> {
    unlocks.iter().collect()
}

#[cfg(test)]
mod tests;
