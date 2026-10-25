//! The v3 key schedule, the encoding the tag covers, the AEAD, and the Shamir split.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use vsss_rs::Gf256;
use zeroize::{Zeroize, Zeroizing};

use crate::App;

pub(super) const AEAD: &str = "xchacha20poly1305";
pub(super) const KDF: &str = "hkdf-sha256";
pub(super) const MAC: &str = "hmac-sha256";

/// Byte strings as length-prefixed items, integers as 8 bytes, and flags as one byte, so two
/// different field lists never encode to the same bytes.
#[derive(Default)]
pub(super) struct Encoder(Vec<u8>);

impl Encoder {
    pub(super) fn bytes(&mut self, bytes: impl AsRef<[u8]>) -> &mut Self {
        let bytes = bytes.as_ref();
        let len = u32::try_from(bytes.len()).expect("vault fields are far below 4 GiB");
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    pub(super) fn int(&mut self, value: u64) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub(super) fn flag(&mut self, value: bool) -> &mut Self {
        self.0.push(u8::from(value));
        self
    }

    /// A `BTreeMap` iterates in key order, and `String` orders by its bytes.
    pub(super) fn map(&mut self, map: &BTreeMap<String, String>) -> &mut Self {
        self.int(map.len() as u64);
        for (key, value) in map {
            self.bytes(key).bytes(value);
        }
        self
    }

    pub(super) fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

fn hkdf(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut okm = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// The key that wraps a `fido2-hmac` entry's value, from its key's hmac-secret output.
pub(super) fn wrap_key(
    app: App,
    output: &[u8; 32],
    salt: &[u8; 32],
    cred_id: &[u8],
) -> Zeroizing<[u8; 32]> {
    let info = Encoder::default()
        .bytes("fido2kit/v3/wrap")
        .bytes(app.name())
        .bytes(cred_id)
        .finish();
    hkdf(output, Some(salt), &info)
}

pub(super) fn secret_key(app: App, data_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let info = Encoder::default()
        .bytes("fido2kit/v3/secret")
        .bytes(app.name())
        .finish();
    hkdf(data_key, None, &info)
}

pub(super) fn mac_key(app: App, data_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let info = Encoder::default()
        .bytes("fido2kit/v3/mac")
        .bytes(app.name())
        .finish();
    hkdf(data_key, None, &info)
}

fn hmac(app: App, data_key: &[u8; 32], encoding: &[u8]) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(mac_key(app, data_key).as_ref())
        .expect("HMAC takes a key of any length");
    mac.update(encoding);
    mac
}

pub(super) fn tag(app: App, data_key: &[u8; 32], encoding: &[u8]) -> [u8; 32] {
    hmac(app, data_key, encoding).finalize().into_bytes().into()
}

/// Compares in constant time.
pub(super) fn tag_matches(app: App, data_key: &[u8; 32], encoding: &[u8], tag: &[u8; 32]) -> bool {
    hmac(app, data_key, encoding).verify_slice(tag).is_ok()
}

pub(super) fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&Key::from(*key))
}

pub(super) fn seal(key: &[u8; 32], aad: &[u8], msg: &[u8]) -> Result<([u8; 24], Vec<u8>)> {
    let nonce = random::<24>()?;
    let ciphertext = cipher(key)
        .encrypt(&XNonce::from(nonce), Payload { msg, aad })
        .map_err(|_| anyhow!("Encryption failed"))?;
    Ok((nonce, ciphertext))
}

pub(super) fn open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    cipher(key)
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

pub(super) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("The random source failed: {e}"))?;
    Ok(bytes)
}

/// Splits `data_key` into `n` shares over GF(256), any `k` of which rebuild it. Share `i` has
/// the x-coordinate `i + 1`.
pub(super) fn split(data_key: &[u8; 32], k: u8, n: usize) -> Result<Vec<Zeroizing<[u8; 32]>>> {
    // vsss-rs takes an infallible source. The OS source just made the data key, so a failure here
    // would be a new fault of the OS, and UnwrapErr turns it into a panic.
    let mut shares = Gf256::split_bytes(usize::from(k), n, data_key, UnwrapErr(SysRng))
        .map_err(|e| anyhow!("Cannot split the data key: {e:?}"))?;
    let result = shares
        .iter()
        .enumerate()
        .map(|(index, share)| {
            ensure!(
                share.len() == 33 && usize::from(share[0]) == index + 1,
                "The data key split has an unexpected layout"
            );
            let mut y = Zeroizing::new([0; 32]);
            y.copy_from_slice(&share[1..]);
            Ok(y)
        })
        .collect();
    shares.iter_mut().for_each(Zeroize::zeroize);
    result
}

/// Rebuilds the data key from shares given as (x-coordinate, value).
pub(super) fn combine(shares: &[(u8, &[u8; 32])]) -> Result<Zeroizing<[u8; 32]>> {
    let mut points: Vec<Vec<u8>> = shares
        .iter()
        .map(|(x, y)| {
            let mut point = Vec::with_capacity(33);
            point.push(*x);
            point.extend_from_slice(*y);
            point
        })
        .collect();
    let joined = Gf256::combine_bytes(&points);
    points.iter_mut().for_each(Zeroize::zeroize);
    let joined = Zeroizing::new(joined.map_err(|e| anyhow!("Cannot join the key shares: {e:?}"))?);
    let key: [u8; 32] = joined
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("The joined key has the wrong length"))?;
    Ok(Zeroizing::new(key))
}
