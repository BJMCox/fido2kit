//! Security-key operations over USB HID. Every call that makes or uses a credential names its
//! [`App`], whose name is the relying-party ID, so one app's credentials never answer another's.

use std::fmt;
use std::sync::{Arc, mpsc};

use anyhow::anyhow;
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::{
    Extension as Gext, GetAssertionArgs,
};
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::{
    Extension as Mext, MakeCredentialArgs,
};
use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, HidParam, LibCfg};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::App;

/// Shown when a key refuses the silent credential lookup that long credential lists need.
const NO_SILENT_CHECK: &str = "This key requires its PIN even to look up credentials, and too many keys are enrolled to check them in one request. Remove enrolled keys you no longer use, or turn off the key's always-require-PIN setting.";

/// One security key's hmac-secret output for its enrolled credential.
#[derive(Clone)]
pub struct Unlock {
    pub cred_id: Vec<u8>,
    pub output: Zeroizing<[u8; 32]>,
}

#[derive(Debug)]
pub enum FidoError {
    NoDevice,
    MultipleDevices,
    WrongPin { retries: Option<i32> },
    PinRequired,
    PinBlocked,
    PinAuthBlocked,
    Timeout,
    NotEnrolled,
    AlreadyEnrolled,
    Other(anyhow::Error),
}

impl fmt::Display for FidoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDevice => write!(f, "Insert your security key."),
            Self::MultipleDevices => write!(f, "Remove all security keys but one."),
            Self::WrongPin { retries: Some(n) } => write!(f, "Wrong PIN. {n} tries left."),
            Self::WrongPin { retries: None } => write!(f, "Wrong PIN."),
            Self::PinRequired => write!(f, "This key has a PIN. Enter it."),
            Self::PinBlocked => write!(
                f,
                "The FIDO2 PIN is blocked. Only a FIDO2 reset with the vendor's tool recovers the key, and it erases all FIDO2 credentials. Use a backup key."
            ),
            Self::PinAuthBlocked => {
                write!(
                    f,
                    "Too many wrong PINs in a row. Remove and reinsert the security key."
                )
            }
            Self::Timeout => write!(f, "No touch detected. Try again."),
            Self::NotEnrolled => write!(f, "This security key is not enrolled."),
            Self::AlreadyEnrolled => write!(f, "This security key is already enrolled."),
            Self::Other(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for FidoError {}

/// True when the same key wants its PIN again: a wrong PIN, or none where one is needed. Any other
/// failure may need another key.
pub fn retry_pin(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<FidoError>(),
        Some(FidoError::WrongPin { .. } | FidoError::PinRequired)
    )
}

/// A plugged-in FIDO device, as the operating system names it.
pub type Device = HidParam;

/// Which plugged-in security key to talk to: the only one, or the one the user touched.
#[derive(Clone)]
pub struct Key(HidParam);

impl Key {
    /// The key at hidapi `path`, for an app that tracks devices itself.
    pub fn from_path(path: String) -> Self {
        Key(HidParam::Path(path))
    }
}

/// The plugged-in FIDO security keys.
pub fn devices() -> Vec<HidParam> {
    ctap_hid_fido2::get_fidokey_devices()
        .into_iter()
        .map(|info| info.param)
        .collect()
}

/// The key to use among `devices`. With one key it is that key. With several, every key blinks
/// until the user touches one (CTAP 2.1 authenticatorSelection), and the others are cancelled.
pub fn select(devices: Vec<HidParam>) -> Result<Key, FidoError> {
    match devices.as_slice() {
        [] => return Err(FidoError::NoDevice),
        [only] => return Ok(Key(only.clone())),
        _ => {}
    }
    let cfg = LibCfg::init();
    let opened: Vec<(HidParam, Arc<FidoKeyHid>)> = devices
        .into_iter()
        .filter_map(|param| {
            let device =
                FidoKeyHidFactory::create_by_params(std::slice::from_ref(&param), &cfg).ok()?;
            Some((param, Arc::new(device)))
        })
        .collect();
    let (sender, touched) = mpsc::channel();
    for (index, (_, device)) in opened.iter().enumerate() {
        let (device, sender) = (Arc::clone(device), sender.clone());
        std::thread::spawn(move || {
            let _ = sender.send((index, device.selection()));
        });
    }
    drop(sender);
    let mut last_error = None;
    for (index, result) in touched {
        match result {
            Ok(()) => {
                // Stops the other keys blinking. A key that already answered ignores the cancel.
                for (other, (_, device)) in opened.iter().enumerate() {
                    if other != index {
                        let _ = device.cancel_selection();
                    }
                }
                return Ok(Key(opened[index].0.clone()));
            }
            Err(error) => last_error = Some(classify(error)),
        }
    }
    // A key without authenticatorSelection (CTAP 2.0) cannot take part, so fall back to one key.
    Err(match last_error {
        Some(FidoError::Timeout) => FidoError::Timeout,
        _ => FidoError::MultipleDevices,
    })
}

/// The PIN in Unicode normalization form C, which CTAP requires before hashing, so a PIN typed
/// or pasted in another but equivalent form still matches. Whitespace stays.
fn nfc(pin: &str) -> Zeroizing<String> {
    // NFC is at most three times its UTF-8 input (UAX #15), so the string never reallocates and
    // leaves no freed copy of the PIN.
    let mut normalized = Zeroizing::new(String::with_capacity(3 * pin.len()));
    normalized.extend(pin.nfc());
    normalized
}

/// The PIN protocol to use with a key that lists `listed`. Protocol 1 stays whenever the key
/// supports it, as every key that worked before does. A key without the list is CTAP 2.0.
fn pin_protocol(listed: &[u32]) -> u8 {
    if listed.contains(&2) && !listed.contains(&1) {
        2
    } else {
        1
    }
}

/// The key's limits for credential lists in one request. 0 means none reported.
struct Limits {
    count: u32,
    id_length: u32,
}

/// Splits `ids` for a key with these limits, or `None` when one plain request fits. IDs longer
/// than `id_length` cannot belong to the key, so they are left out.
fn chunks<'a>(ids: &[&'a [u8]], count: u32, id_length: u32) -> Option<Vec<Vec<&'a [u8]>>> {
    let kept: Vec<&[u8]> = ids
        .iter()
        .copied()
        .filter(|id| id_length == 0 || id.len() <= id_length as usize)
        .collect();
    if kept.len() == ids.len() && (count == 0 || ids.len() <= count as usize) {
        return None;
    }
    let size = if count == 0 {
        kept.len()
    } else {
        count as usize
    };
    Some(kept.chunks(size.max(1)).map(<[_]>::to_vec).collect())
}

/// The arguments for making a credential. `None` for `pin` asks without a PIN or user
/// verification, and `hmac_secret` asks for a credential that can derive secrets.
fn make_args<'a>(
    app: App,
    challenge: &[u8; 32],
    pin: Option<&'a str>,
    exclude: &[&[u8]],
    user: Option<&PublicKeyCredentialUserEntity>,
    hmac_secret: bool,
) -> MakeCredentialArgs<'a> {
    let builder = MakeCredentialArgsBuilder::new(app.name(), challenge);
    let mut builder = match pin {
        Some(pin) => builder.pin(pin),
        None => builder.without_pin_and_uv(),
    };
    if hmac_secret {
        builder = builder.extensions(&[Mext::HmacSecret(Some(true))]);
    }
    if let Some(user) = user {
        builder = builder.user_entity(user);
    }
    for id in exclude {
        builder = builder.exclude_authenticator(id);
    }
    builder.build()
}

/// The arguments for an assertion over `cred_ids`. With `hmac`, it asks with the PIN for the
/// hmac-secret output of the salt. Without, it asks with no PIN, touch, or extension (CTAP
/// up=false), which only finds the credential the key holds.
fn assert_args<'a>(
    app: App,
    challenge: &[u8; 32],
    cred_ids: &[&[u8]],
    hmac: Option<(&'a str, &[u8; 32])>,
) -> GetAssertionArgs<'a> {
    let builder = GetAssertionArgsBuilder::new(app.name(), challenge);
    let mut builder = match hmac {
        Some((pin, salt)) => builder
            .pin(pin)
            .extensions(&[Gext::HmacSecret(Some(*salt))]),
        None => builder.without_pin_and_uv().without_up(),
    };
    for id in cred_ids {
        builder = builder.add_credential_id(id);
    }
    builder.build()
}

/// The credential in `parts` that the key holds, found without a PIN or a touch (CTAP up=false),
/// so each request stays within the key's list limits.
fn preflight(
    app: App,
    device: &FidoKeyHid,
    parts: &[Vec<&[u8]>],
) -> Result<Option<Vec<u8>>, FidoError> {
    for part in parts {
        let challenge = random::<32>()?;
        match device
            .get_assertion_with_args(&assert_args(app, &challenge, part, None))
            .map_err(classify)
        {
            Ok(assertions) => {
                let id = assertions
                    .into_iter()
                    .next()
                    .map(|a| a.credential_id)
                    .unwrap_or_default();
                return match (id.is_empty(), part.as_slice()) {
                    (false, _) => Ok(Some(id)),
                    (true, [only]) => Ok(Some(only.to_vec())),
                    (true, _) => Err(FidoError::Other(anyhow!(
                        "The key returned no credential ID"
                    ))),
                };
            }
            Err(FidoError::NotEnrolled) => {}
            Err(other) => return Err(other),
        }
    }
    Ok(None)
}

/// A PIN demand can only come from the silent preflight here, because the other requests carry
/// the PIN. Asking for the PIN again would loop, so it becomes a final error.
fn no_silent_check(error: FidoError) -> FidoError {
    match error {
        FidoError::PinRequired => FidoError::Other(anyhow!(NO_SILENT_CHECK)),
        other => other,
    }
}

/// Makes a non-resident hmac-secret credential and returns its output for `salt`. Needs two touches.
pub fn enroll(
    app: App,
    key: &Key,
    pin: &str,
    salt: &[u8; 32],
    exclude: &[&[u8]],
) -> Result<Unlock, FidoError> {
    enroll_with_pin(app, key, pin, salt, exclude).map_err(no_silent_check)
}

fn enroll_with_pin(
    app: App,
    key: &Key,
    pin: &str,
    salt: &[u8; 32],
    exclude: &[&[u8]],
) -> Result<Unlock, FidoError> {
    let (device, limits) = open_for_pin(key)?;
    let pin = nfc(pin);
    let limited = chunks(exclude, limits.count, limits.id_length);
    if let Some(parts) = &limited
        && preflight(app, &device, parts)?.is_some()
    {
        return Err(FidoError::AlreadyEnrolled);
    }
    // The preflight already checked every credential that would not fit in one list.
    let exclude: &[&[u8]] = if limited.is_some() { &[] } else { exclude };
    let challenge = random::<32>()?;
    let args = make_args(app, &challenge, Some(pin.as_str()), exclude, None, true);
    let attestation = device
        .make_credential_with_args(&args)
        .map_err(|e| with_retries(&device, e))?;
    if !attestation
        .extensions
        .iter()
        .any(|e| matches!(e, Mext::HmacSecret(Some(true))))
    {
        return Err(FidoError::Other(anyhow!(
            "This key does not support hmac-secret"
        )));
    }
    assert_hmac(
        app,
        &device,
        &pin,
        salt,
        &[&attestation.credential_descriptor.id],
    )
}

/// Returns the hmac-secret output of whichever enrolled credential the inserted key holds.
pub fn derive(
    app: App,
    key: &Key,
    pin: &str,
    salt: &[u8; 32],
    cred_ids: &[&[u8]],
) -> Result<Unlock, FidoError> {
    derive_with_pin(app, key, pin, salt, cred_ids).map_err(no_silent_check)
}

fn derive_with_pin(
    app: App,
    key: &Key,
    pin: &str,
    salt: &[u8; 32],
    cred_ids: &[&[u8]],
) -> Result<Unlock, FidoError> {
    let (device, limits) = open_for_pin(key)?;
    let pin = nfc(pin);
    match chunks(cred_ids, limits.count, limits.id_length) {
        None => assert_hmac(app, &device, &pin, salt, cred_ids),
        Some(parts) => {
            let found = preflight(app, &device, &parts)?.ok_or(FidoError::NotEnrolled)?;
            assert_hmac(app, &device, &pin, salt, &[&found])
        }
    }
}

fn assert_hmac(
    app: App,
    device: &FidoKeyHid,
    pin: &str,
    salt: &[u8; 32],
    cred_ids: &[&[u8]],
) -> Result<Unlock, FidoError> {
    let challenge = random::<32>()?;
    let mut assertion = device
        .get_assertion_with_args(&assert_args(app, &challenge, cred_ids, Some((pin, salt))))
        .map_err(|e| with_retries(device, e))?
        .into_iter()
        .next()
        .ok_or_else(|| FidoError::Other(anyhow!("The key returned no assertion")))?;
    let output = assertion
        .extensions
        .iter()
        .find_map(|e| match e {
            Gext::HmacSecret(Some(output)) => Some(Zeroizing::new(*output)),
            _ => None,
        })
        .ok_or_else(|| FidoError::Other(anyhow!("The key returned no hmac-secret output")))?;
    // Only the Zeroizing copy may keep the wrapping secret.
    for extension in &mut assertion.extensions {
        if let Gext::HmacSecret(Some(bytes)) = extension {
            bytes.zeroize();
        }
    }
    // CTAP lets the key omit the credential ID when the allow list has one entry.
    let cred_id = match (assertion.credential_id.is_empty(), cred_ids) {
        (true, [only]) => only.to_vec(),
        _ => assertion.credential_id,
    };
    Ok(Unlock { cred_id, output })
}

/// Makes a non-resident credential for `app` and returns its ID. Needs a touch, and the PIN when
/// the key has one. A blank `pin` asks without one.
pub fn make_credential(app: App, key: &Key, pin: &str) -> Result<Vec<u8>, FidoError> {
    let normalized = nfc(pin);
    let device = if normalized.is_empty() {
        open_plain(key)?
    } else {
        open_for_pin(key)?.0
    };
    let challenge = random::<32>()?;
    let user_id = random::<16>()?;
    let user =
        PublicKeyCredentialUserEntity::new(Some(&user_id), Some(app.name()), Some(app.name()));
    let pin = (!normalized.is_empty()).then_some(normalized.as_str());
    let args = make_args(app, &challenge, pin, &[], Some(&user), false);
    let attestation = device
        .make_credential_with_args(&args)
        .map_err(|e| with_retries(&device, e))?;
    Ok(attestation.credential_descriptor.id)
}

/// Asks `key`, without a touch or PIN, which of `credentials` it holds, and returns that ID.
pub fn silent_assertion(app: App, key: &Key, credentials: &[&[u8]]) -> Result<Vec<u8>, FidoError> {
    let device = open_plain(key)?;
    let challenge = random::<32>()?;
    let assertion = device
        .get_assertion_with_args(&assert_args(app, &challenge, credentials, None))
        .map_err(classify)?
        .into_iter()
        .next()
        .ok_or_else(|| FidoError::Other(anyhow!("The key returned no assertion")))?;
    // CTAP lets the key omit the credential ID when the allow list has one entry.
    Ok(match (assertion.credential_id.is_empty(), credentials) {
        (true, [only]) => only.to_vec(),
        _ => assertion.credential_id,
    })
}

/// Opens the key with a PIN protocol it supports, and reads its credential list limits.
fn open_for_pin(key: &Key) -> Result<(FidoKeyHid, Limits), FidoError> {
    let device = open_plain(key)?;
    // A key that cannot report its info counts as CTAP 2.0: protocol 1 and no list limits.
    let info = device.get_info().unwrap_or_default();
    let limits = Limits {
        count: info.max_credential_count_in_list,
        id_length: info.max_credential_id_length,
    };
    let protocol = pin_protocol(&info.pin_uv_auth_protocols);
    Ok((device.with_pin_protocol_version(protocol), limits))
}

/// Opens the key without asking it anything, so a silent check stays one CTAP round trip.
fn open_plain(key: &Key) -> Result<FidoKeyHid, FidoError> {
    FidoKeyHidFactory::create_by_params(std::slice::from_ref(&key.0), &LibCfg::init())
        .map_err(classify)
}

fn random<const N: usize>() -> Result<[u8; N], FidoError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|e| FidoError::Other(anyhow!("The random source failed: {e}")))?;
    Ok(bytes)
}

fn with_retries(device: &FidoKeyHid, error: anyhow::Error) -> FidoError {
    match classify(error) {
        FidoError::WrongPin { .. } => FidoError::WrongPin {
            retries: device.get_pin_retries().ok(),
        },
        other => other,
    }
}

/// Maps ctap-hid-fido2's error text, which carries the CTAP status name, to the cases the UI handles.
fn classify(error: anyhow::Error) -> FidoError {
    let text = format!("{error:#}");
    let cases = [
        ("FIDO device not found", FidoError::NoDevice),
        ("Multiple FIDO devices", FidoError::MultipleDevices),
        (
            "CTAP2_ERR_PIN_INVALID",
            FidoError::WrongPin { retries: None },
        ),
        ("CTAP2_ERR_PIN_BLOCKED", FidoError::PinBlocked),
        ("CTAP2_ERR_PIN_AUTH_BLOCKED", FidoError::PinAuthBlocked),
        ("CTAP2_ERR_USER_ACTION_TIMEOUT", FidoError::Timeout),
        // Some authenticators report a touch timeout with this older status name.
        ("CTAP2_ERR_ACTION_TIMEOUT", FidoError::Timeout),
        ("CTAP2_ERR_NO_CREDENTIALS", FidoError::NotEnrolled),
        ("CTAP2_ERR_CREDENTIAL_EXCLUDED", FidoError::AlreadyEnrolled),
        ("CTAP2_ERR_PIN_REQUIRED", FidoError::PinRequired),
        ("CTAP2_ERR_PUAT_REQUIRED", FidoError::PinRequired),
    ];
    cases
        .into_iter()
        .find(|(needle, _)| text.contains(needle))
        .map_or(FidoError::Other(error), |(_, case)| case)
}

#[cfg(test)]
mod tests;
