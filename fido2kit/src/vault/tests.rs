use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::XNonce;
use chacha20poly1305::aead::{Aead, Payload};

const APP: App = App::new("fido2kpxc");

// Computed independently from the spec with Python's hmac and hashlib.
const WRAP_KEY_VECTOR: &str = "0b0fcb637d812a17cd0d98a1e411484f101427d50ca30c0231e33979b3ab5401";
const SECRET_KEY_VECTOR: &str = "9debe5db5616146b6cbee0e305744dd41caa8aa3f6f373c3531c522cb2055eaf";
const MAC_KEY_VECTOR: &str = "b367ea7092c3653f7360f6efa7b7a1761f99b2eb052ea28ea3481ebf29f0261c";
const TAG_VECTOR: &str = "badd2f78c4851884a3edd2092e9db64161027b5ec167fba01bd57dfb151960c1";

fn unlock(id: u8, output: u8) -> Unlock {
    Unlock {
        cred_id: vec![id; 16],
        output: Zeroizing::new([output; 32]),
    }
}

fn enrollment(id: u8, output: u8) -> Enrollment {
    Enrollment {
        unlock: unlock(id, output),
        aaguid: [id; 16],
        uv: true,
    }
}

fn one_key_vault(secret: &[u8]) -> Vault {
    Vault::create(APP, [7; 32], "primary", &enrollment(1, 10), ANY, secret).unwrap()
}

fn two_key_vault(secret: &[u8]) -> Vault {
    let mut vault = one_key_vault(secret);
    vault
        .add_key(&[unlock(1, 10)], "backup", &enrollment(2, 20))
        .unwrap();
    vault
}

/// Keys 1 to `n`, with `k` of them needed.
fn threshold_vault(k: u8, n: u8) -> Vault {
    let mut vault = one_key_vault(b"hunter2");
    let mut present = vec![unlock(1, 10)];
    for id in 2..=n {
        vault
            .add_key(&present, &format!("key{id}"), &enrollment(id, id * 10))
            .unwrap();
        present.push(unlock(id, id * 10));
    }
    vault.set_threshold(&present, k).unwrap();
    vault
}

fn open(vault: &Vault, key: Unlock, name: &str) -> Vec<u8> {
    vault.open(&[key], Some(name)).unwrap().to_vec()
}

fn parse(text: &str) -> Result<Vault> {
    Vault::parse(APP, text, false)
}

fn round_trip(vault: &Vault) -> Vault {
    parse(&vault.to_text().unwrap()).unwrap()
}

/// The vault's file text after `edit`, as someone with write access could leave it.
/// A change to a vault file's TOML.
type Edit = Box<dyn Fn(&mut toml::Table)>;

fn edited(vault: &Vault, edit: impl FnOnce(&mut toml::Table)) -> String {
    let mut table: toml::Table = vault.to_text().unwrap().parse().unwrap();
    edit(&mut table);
    toml::to_string(&table).unwrap()
}

fn entry(table: &mut toml::Table, list: &str, index: usize) -> toml::Table {
    table[list].as_array().unwrap()[index]
        .as_table()
        .unwrap()
        .clone()
}

fn set_entry(table: &mut toml::Table, list: &str, index: usize, value: toml::Table) {
    table.get_mut(list).unwrap().as_array_mut().unwrap()[index] = toml::Value::Table(value);
}

fn b64(bytes: &[u8]) -> toml::Value {
    toml::Value::String(STANDARD.encode(bytes))
}

fn error_of<T>(result: Result<T>) -> String {
    format!("{:#}", result.err().expect("an error"))
}

#[test]
fn either_key_opens_the_vault_after_a_save_and_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    two_key_vault(b"hunter2").save(&path, true).unwrap();
    let vault = Vault::load(APP, &path).unwrap();
    assert_eq!(vault.version(), 3);
    assert_eq!(vault.salt(), [7; 32]);
    assert_eq!(open(&vault, unlock(1, 10), "pdb.kdbx"), b"hunter2");
    assert_eq!(open(&vault, unlock(2, 20), "pdb.kdbx"), b"hunter2");
}

#[test]
fn exact_database_name_beats_the_catch_all() {
    let mut vault = two_key_vault(b"default");
    vault
        .set_secret(&[unlock(1, 10)], "work.kdbx", b"work")
        .unwrap();
    assert_eq!(open(&vault, unlock(2, 20), "work.kdbx"), b"work");
    assert_eq!(open(&vault, unlock(2, 20), "home.kdbx"), b"default");
}

#[test]
fn unknown_database_without_a_catch_all_has_no_secret() {
    let vault = Vault::create(
        APP,
        [7; 32],
        "primary",
        &enrollment(1, 10),
        "work.kdbx",
        b"work",
    )
    .unwrap();
    assert!(!vault.has_secret_for(Some("home.kdbx")));
    assert!(vault.open(&[unlock(1, 10)], Some("home.kdbx")).is_err());
    assert_eq!(open(&vault, unlock(1, 10), "work.kdbx"), b"work");
}

#[test]
fn set_secret_keeps_every_key_working() {
    let mut vault = two_key_vault(b"old");
    vault.set_secret(&[unlock(1, 10)], ANY, b"new").unwrap();
    assert_eq!(open(&vault, unlock(2, 20), "pdb.kdbx"), b"new");
    assert_eq!(vault.names(), vec![ANY]);
}

#[test]
fn remove_secret_falls_back_to_the_catch_all() {
    let mut vault = two_key_vault(b"default");
    vault
        .set_secret(&[unlock(1, 10)], "work.kdbx", b"work")
        .unwrap();
    vault.remove_secret(&[unlock(1, 10)], "work.kdbx").unwrap();
    assert_eq!(open(&vault, unlock(1, 10), "work.kdbx"), b"default");
    assert!(vault.remove_secret(&[unlock(1, 10)], ANY).is_err());
}

#[test]
fn remove_key_keeps_the_other_keys_working() {
    let mut vault = two_key_vault(b"hunter2");
    vault
        .set_secret(&[unlock(1, 10)], "work.kdbx", b"work")
        .unwrap();
    vault
        .add_key(&[unlock(1, 10)], "third", &enrollment(3, 30))
        .unwrap();
    vault
        .remove_keys(&["backup"], &[unlock(1, 10), unlock(3, 30)])
        .unwrap();
    assert!(vault.open(&[unlock(2, 20)], None).is_err());
    assert_eq!(open(&vault, unlock(1, 10), "pdb.kdbx"), b"hunter2");
    assert_eq!(open(&vault, unlock(3, 30), "work.kdbx"), b"work");
}

#[test]
fn removed_key_cannot_read_vaults_written_after_removal() {
    let mut vault = two_key_vault(b"hunter2");
    let old_copy = round_trip(&vault);
    vault.remove_keys(&["backup"], &[unlock(1, 10)]).unwrap();
    // The removed key still opens its old copy, so it knows the old data key, which must no
    // longer be the vault's.
    let old_key = old_copy.data_key(&[&unlock(2, 20)]).unwrap();
    let new_key = vault.data_key(&[&unlock(1, 10)]).unwrap();
    assert_ne!(*old_key, *new_key);
}

#[test]
fn remove_key_refuses_the_last_key() {
    let mut vault = one_key_vault(b"hunter2");
    assert!(vault.remove_keys(&["primary"], &[]).is_err());
    assert_eq!(open(&vault, unlock(1, 10), "pdb.kdbx"), b"hunter2");
}

#[test]
fn two_lost_keys_are_removed_at_once_with_only_the_kept_keys() {
    let mut vault = two_key_vault(b"hunter2");
    for (label, id) in [("third", 3), ("fourth", 4)] {
        vault
            .add_key(&[unlock(1, 10)], label, &enrollment(id, id * 10))
            .unwrap();
    }
    vault
        .remove_keys(&["backup", "third"], &[unlock(1, 10), unlock(4, 40)])
        .unwrap();
    assert!(vault.open(&[unlock(2, 20)], None).is_err());
    assert!(vault.open(&[unlock(3, 30)], None).is_err());
    assert_eq!(open(&vault, unlock(1, 10), "pdb.kdbx"), b"hunter2");
    assert_eq!(open(&vault, unlock(4, 40), "pdb.kdbx"), b"hunter2");
    assert_eq!(vault.kept_keys(&[]).unwrap().len(), 2);
}

#[test]
fn removing_every_key_fails_and_changes_nothing() {
    let mut vault = two_key_vault(b"hunter2");
    assert!(vault.remove_keys(&["primary", "backup"], &[]).is_err());
    assert_eq!(open(&vault, unlock(2, 20), "pdb.kdbx"), b"hunter2");
}

#[test]
fn an_unknown_label_fails_and_changes_nothing() {
    let mut vault = two_key_vault(b"hunter2");
    let before = vault.to_text().unwrap();
    assert!(
        vault
            .remove_keys(&["backup", "spare"], &[unlock(1, 10)])
            .is_err()
    );
    assert_eq!(vault.to_text().unwrap(), before);
}

#[test]
fn kept_keys_lists_the_keys_that_need_a_touch() {
    let mut vault = two_key_vault(b"hunter2");
    vault
        .add_key(&[unlock(1, 10)], "third", &enrollment(3, 30))
        .unwrap();
    let kept: Vec<&str> = vault
        .kept_keys(&["backup"])
        .unwrap()
        .into_iter()
        .map(|(label, _)| label)
        .collect();
    assert_eq!(kept, ["primary", "third"]);
}

#[test]
fn swapped_cred_ids_fail_to_unwrap() {
    // Both keys share one output, so only the cred_id binding can reject the swap.
    let mut vault = one_key_vault(b"hunter2");
    vault
        .add_key(&[unlock(1, 10)], "backup", &enrollment(2, 10))
        .unwrap();
    let text = edited(&vault, |t| {
        let (mut first, mut second) = (entry(t, "keys", 0), entry(t, "keys", 1));
        let id = first["cred_id"].clone();
        first.insert("cred_id".into(), second["cred_id"].clone());
        second.insert("cred_id".into(), id);
        set_entry(t, "keys", 0, first);
        set_entry(t, "keys", 1, second);
    });
    assert!(parse(&text).unwrap().open(&[unlock(2, 10)], None).is_err());
}

#[test]
fn another_app_cannot_open_a_v3_vault() {
    let text = two_key_vault(b"hunter2").to_text().unwrap();
    let vault = Vault::parse(App::new("fido2tomb"), &text, false).unwrap();
    assert!(vault.open(&[unlock(1, 10)], None).is_err());
}

#[test]
fn every_field_is_covered_by_the_tag() {
    let mut vault = two_key_vault(b"hunter2");
    let both = [unlock(1, 10), unlock(2, 20)];
    vault.set_secret(&both[..1], "work.kdbx", b"work").unwrap();
    vault.set_pending(&both[..1], "work.kdbx", b"next").unwrap();
    vault.set_meta(&both[..1], "app.mode", "a").unwrap();
    vault
        .set_secret_meta(&both[..1], "work.kdbx", "app.hash", "Argon2")
        .unwrap();
    let edits: Vec<(&str, Edit)> = vec![
        (
            "label",
            Box::new(|t| {
                let mut key = entry(t, "keys", 1);
                key.insert("label".into(), "spare".into());
                set_entry(t, "keys", 1, key);
            }),
        ),
        (
            "swapped labels",
            Box::new(|t| {
                let (mut first, mut second) = (entry(t, "keys", 0), entry(t, "keys", 1));
                first.insert("label".into(), "backup".into());
                second.insert("label".into(), "primary".into());
                set_entry(t, "keys", 0, first);
                set_entry(t, "keys", 1, second);
            }),
        ),
        (
            "every salt",
            Box::new(|t| {
                for index in 0..2 {
                    let mut key = entry(t, "keys", index);
                    key.insert("salt".into(), b64(&[8; 32]));
                    set_entry(t, "keys", index, key);
                }
            }),
        ),
        (
            "kind",
            Box::new(|t| {
                let mut key = entry(t, "keys", 1);
                key.insert("kind".into(), "fido2-hmac-v2".into());
                set_entry(t, "keys", 1, key);
            }),
        ),
        (
            "aaguid",
            Box::new(|t| {
                let mut key = entry(t, "keys", 1);
                key.insert("aaguid".into(), b64(&[9; 16]));
                set_entry(t, "keys", 1, key);
            }),
        ),
        (
            "created",
            Box::new(|t| {
                let mut key = entry(t, "keys", 1);
                key.insert("created".into(), 5.into());
                set_entry(t, "keys", 1, key);
            }),
        ),
        (
            "uv",
            Box::new(|t| {
                let mut key = entry(t, "keys", 1);
                key.insert("uv".into(), false.into());
                set_entry(t, "keys", 1, key);
            }),
        ),
        (
            "generation",
            Box::new(|t| {
                let next = t["generation"].as_integer().unwrap() + 1;
                t.insert("generation".into(), next.into());
            }),
        ),
        (
            "vault meta value",
            Box::new(|t| {
                let mut meta = toml::Table::new();
                meta.insert("app.mode".into(), "b".into());
                t.insert("meta".into(), meta.into());
            }),
        ),
        (
            "added vault meta key",
            Box::new(|t| {
                let mut meta = t["meta"].as_table().unwrap().clone();
                meta.insert("app.extra".into(), "x".into());
                t.insert("meta".into(), meta.into());
            }),
        ),
        (
            "secret meta",
            Box::new(|t| {
                let mut secret = entry(t, "secrets", 1);
                let mut meta = toml::Table::new();
                meta.insert("app.hash".into(), "SHA-512".into());
                secret.insert("meta".into(), meta.into());
                set_entry(t, "secrets", 1, secret);
            }),
        ),
        (
            "dropped pending value",
            Box::new(|t| {
                let mut secret = entry(t, "secrets", 1);
                secret.remove("pending_nonce");
                secret.remove("pending_ciphertext");
                set_entry(t, "secrets", 1, secret);
            }),
        ),
        (
            "reordered keys",
            Box::new(|t| {
                let (first, second) = (entry(t, "keys", 0), entry(t, "keys", 1));
                set_entry(t, "keys", 0, second);
                set_entry(t, "keys", 1, first);
            }),
        ),
        (
            "reordered secrets",
            Box::new(|t| {
                let (first, second) = (entry(t, "secrets", 0), entry(t, "secrets", 1));
                set_entry(t, "secrets", 0, second);
                set_entry(t, "secrets", 1, first);
            }),
        ),
        (
            "removed key",
            Box::new(|t| {
                t.get_mut("keys").unwrap().as_array_mut().unwrap().remove(1);
            }),
        ),
        (
            "removed secret",
            Box::new(|t| {
                t.get_mut("secrets")
                    .unwrap()
                    .as_array_mut()
                    .unwrap()
                    .remove(1);
            }),
        ),
        (
            "added key",
            Box::new(|t| {
                let mut copy = entry(t, "keys", 0);
                copy.insert("label".into(), "copy".into());
                copy.insert("cred_id".into(), b64(&[3; 16]));
                t.get_mut("keys")
                    .unwrap()
                    .as_array_mut()
                    .unwrap()
                    .push(copy.into());
            }),
        ),
        (
            "changed tag",
            Box::new(|t| {
                t.insert("tag".into(), b64(&[0; 32]));
            }),
        ),
    ];
    // An edit that changes nothing passes, so each rejection below comes from its change.
    parse(&edited(&vault, |_| {}))
        .unwrap()
        .verify(&both[..1])
        .unwrap();
    for (what, edit) in edits {
        let text = edited(&vault, |t| edit(t));
        let rejected = parse(&text).and_then(|v| v.verify(&both[..1]));
        assert!(rejected.is_err(), "{what} was accepted");
    }
    let removed_tag = edited(&vault, |t| {
        t.remove("tag");
    });
    assert!(parse(&removed_tag).is_err());
}

#[test]
fn a_label_swap_stops_remove_keys_before_any_change() {
    let swapped = edited(&two_key_vault(b"hunter2"), |t| {
        let (mut first, mut second) = (entry(t, "keys", 0), entry(t, "keys", 1));
        first.insert("label".into(), "backup".into());
        second.insert("label".into(), "primary".into());
        set_entry(t, "keys", 0, first);
        set_entry(t, "keys", 1, second);
    });
    // The owner holds both keys and retires "backup", which now labels key 1.
    let mut vault = parse(&swapped).unwrap();
    let before = vault.to_text().unwrap();
    let error = error_of(vault.remove_keys(&["backup"], &[unlock(1, 10), unlock(2, 20)]));
    assert!(error.contains("changed outside fido2kpxc"), "{error}");
    assert_eq!(vault.to_text().unwrap(), before);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_key_schedule_matches_its_test_vectors() {
    let app = App::new("fido2veracrypt");
    assert_eq!(
        hex(&*crypto::wrap_key(app, &[1; 32], &[2; 32], &[3; 16])),
        WRAP_KEY_VECTOR
    );
    assert_eq!(hex(&*crypto::secret_key(app, &[4; 32])), SECRET_KEY_VECTOR);
    assert_eq!(hex(&*crypto::mac_key(app, &[4; 32])), MAC_KEY_VECTOR);
}

/// A small vault with fixed bytes, so its tag pins the encoding.
fn fixed_vault() -> Vault {
    let mut key_meta = BTreeMap::new();
    key_meta.insert("app.note".to_owned(), "n".to_owned());
    let mut meta = BTreeMap::new();
    meta.insert("app.mode".to_owned(), "fast".to_owned());
    Vault {
        format: Format::V3,
        threshold: 1,
        generation: 2,
        meta,
        keys: vec![
            KeyEntry {
                kind: KeyKind::Fido2Hmac,
                label: "primary".into(),
                cred_id: vec![1; 16],
                salt: [7; 32],
                share: 0,
                nonce: [2; 24],
                wrapped: vec![3; 48],
                aaguid: Some([4; 16]),
                created: Some(1_761_400_000),
                uv: Some(true),
                meta: key_meta,
            },
            KeyEntry {
                kind: KeyKind::Fido2HmacV2,
                label: "old".into(),
                cred_id: vec![5; 16],
                salt: [7; 32],
                share: 0,
                nonce: [6; 24],
                wrapped: vec![7; 48],
                aaguid: None,
                created: None,
                uv: None,
                meta: BTreeMap::new(),
            },
        ],
        secrets: vec![SecretEntry {
            name: "*".into(),
            current: Sealed {
                nonce: [8; 24],
                ciphertext: vec![9; 20],
            },
            pending: Some(Sealed {
                nonce: [10; 24],
                ciphertext: vec![11; 20],
            }),
            meta: BTreeMap::new(),
        }],
        tag: [0; 32],
        loaded: None,
        app: App::new("fido2veracrypt"),
    }
}

#[test]
fn the_tag_of_a_fixed_vault_matches_its_test_vector() {
    assert_eq!(hex(&fixed_vault().compute_tag(&[4; 32])), TAG_VECTOR);
}

#[test]
fn a_pending_value_cannot_pass_as_the_current_one() {
    let mut vault = one_key_vault(b"current");
    let key = [unlock(1, 10)];
    vault.set_pending(&key, ANY, b"pending").unwrap();
    let data_key = vault.data_key(&[&key[0]]).unwrap();
    let secret = &mut vault.secrets[0];
    let pending = secret.pending.take().unwrap();
    secret.pending = Some(std::mem::replace(&mut secret.current, pending));
    vault.tag = vault.compute_tag(&data_key);
    assert!(vault.open(&key, None).is_err());
    assert!(vault.open_pending(&key, ANY).is_err());
}

#[test]
fn a_secret_moved_to_another_name_fails_to_open() {
    let mut vault = one_key_vault(b"home");
    let key = [unlock(1, 10)];
    vault.set_secret(&key, "work.kdbx", b"work").unwrap();
    let data_key = vault.data_key(&[&key[0]]).unwrap();
    vault.secrets[1].name = "home.kdbx".into();
    vault.tag = vault.compute_tag(&data_key);
    assert!(vault.open(&key, Some("home.kdbx")).is_err());
}

#[test]
fn a_share_moved_to_another_key_fails_to_unwrap() {
    let mut vault = threshold_vault(2, 3);
    let (first, second) = (vault.keys[0].clone(), vault.keys[1].clone());
    vault.keys[0].wrapped = second.wrapped;
    vault.keys[0].nonce = second.nonce;
    vault.keys[1].wrapped = first.wrapped;
    vault.keys[1].nonce = first.nonce;
    assert!(vault.open(&[unlock(1, 10), unlock(2, 20)], None).is_err());
}

#[test]
fn any_k_keys_open_a_threshold_vault_and_fewer_do_not() {
    let vault = round_trip(&threshold_vault(3, 5));
    assert_eq!(vault.threshold(), 3);
    let keys: Vec<Unlock> = (1..=5).map(|id| unlock(id, id * 10)).collect();
    for a in 0..5 {
        for b in a + 1..5 {
            let pair = [keys[a].clone(), keys[b].clone()];
            assert!(vault.open(&pair, None).is_err());
            for c in b + 1..5 {
                let three = [keys[a].clone(), keys[b].clone(), keys[c].clone()];
                assert_eq!(vault.open(&three, None).unwrap().as_slice(), b"hunter2");
            }
        }
    }
}

#[test]
fn changing_the_keys_of_a_threshold_vault_needs_every_key() {
    let mut vault = threshold_vault(2, 3);
    let all: Vec<Unlock> = (1..=3).map(|id| unlock(id, id * 10)).collect();
    assert!(
        vault
            .add_key(&all[..2], "fourth", &enrollment(4, 40))
            .is_err()
    );
    vault.add_key(&all, "fourth", &enrollment(4, 40)).unwrap();
    assert!(vault.set_threshold(&all, 3).is_err());
    assert_eq!(
        vault
            .open(&[unlock(4, 40), unlock(1, 10)], None)
            .unwrap()
            .as_slice(),
        b"hunter2"
    );
}

#[test]
fn remove_keys_refuses_to_keep_fewer_keys_than_the_threshold() {
    let mut vault = threshold_vault(2, 3);
    let kept = [unlock(1, 10)];
    assert!(vault.remove_keys(&["key2", "key3"], &kept).is_err());
    vault
        .remove_keys(&["key3"], &[unlock(1, 10), unlock(2, 20)])
        .unwrap();
    assert!(vault.open(&[unlock(3, 30), unlock(1, 10)], None).is_err());
    assert_eq!(
        vault
            .open(&[unlock(1, 10), unlock(2, 20)], None)
            .unwrap()
            .as_slice(),
        b"hunter2"
    );
}

#[test]
fn a_pending_value_commits_or_discards() {
    let mut vault = two_key_vault(b"old");
    let key = [unlock(1, 10)];
    vault.set_pending(&key, ANY, b"new").unwrap();
    assert!(vault.has_pending(ANY));
    assert_eq!(open(&vault, unlock(2, 20), "x"), b"old");
    assert_eq!(
        vault.open_pending(&key, ANY).unwrap().unwrap().as_slice(),
        b"new"
    );
    vault.discard_pending(&key, ANY).unwrap();
    assert!(vault.open_pending(&key, ANY).unwrap().is_none());
    vault.set_pending(&key, ANY, b"new").unwrap();
    vault.commit_pending(&key, ANY).unwrap();
    assert!(!vault.has_pending(ANY));
    assert_eq!(open(&vault, unlock(2, 20), "x"), b"new");
}

#[test]
fn a_pending_value_survives_remove_keys_and_a_reload() {
    let mut vault = two_key_vault(b"old");
    vault.set_pending(&[unlock(1, 10)], ANY, b"new").unwrap();
    vault.remove_keys(&["backup"], &[unlock(1, 10)]).unwrap();
    let vault = round_trip(&vault);
    assert_eq!(
        vault
            .open_pending(&[unlock(1, 10)], ANY)
            .unwrap()
            .unwrap()
            .as_slice(),
        b"new"
    );
}

#[test]
fn the_generation_rises_with_every_change() {
    let mut vault = one_key_vault(b"a");
    assert_eq!(vault.generation(), 1);
    vault.set_secret(&[unlock(1, 10)], ANY, b"b").unwrap();
    vault.set_meta(&[unlock(1, 10)], "app.mode", "x").unwrap();
    assert_eq!(round_trip(&vault).generation(), 3);
}

#[test]
fn meta_round_trips_and_its_limits_hold() {
    let mut vault = one_key_vault(b"a");
    let key = [unlock(1, 10)];
    vault.set_meta(&key, "app.mode", "fast").unwrap();
    vault
        .set_secret_meta(&key, ANY, "app.hash", "Argon2")
        .unwrap();
    let vault = round_trip(&vault);
    assert_eq!(vault.meta()["app.mode"], "fast");
    assert_eq!(vault.secret_meta(ANY).unwrap()["app.hash"], "Argon2");
    let mut vault = vault;
    assert!(vault.set_meta(&key, "Bad Key", "x").is_err());
    assert!(vault.set_meta(&key, "app.long", &"x".repeat(1025)).is_err());
    for index in 0..63 {
        vault.set_meta(&key, &format!("app.k{index}"), "x").unwrap();
    }
    assert!(vault.set_meta(&key, "app.one-too-many", "x").is_err());
}

#[test]
fn keys_report_their_enrollment_details() {
    let vault = round_trip(&two_key_vault(b"a"));
    let keys = vault.keys();
    assert_eq!(keys[1].label, "backup");
    assert_eq!(keys[1].kind, KeyKind::Fido2Hmac);
    assert_eq!(keys[1].aaguid, Some([2; 16]));
    assert_eq!(keys[1].uv, Some(true));
    assert!(keys[1].created.is_some());
}

#[test]
fn a_v3_file_with_two_different_salts_is_refused() {
    let text = edited(&two_key_vault(b"a"), |t| {
        let mut key = entry(t, "keys", 1);
        key.insert("salt".into(), b64(&[8; 32]));
        set_entry(t, "keys", 1, key);
    });
    assert!(parse(&text).is_err());
}

#[test]
fn invalid_v3_files_are_refused() {
    let vault = two_key_vault(b"a");
    let threshold = round_trip(&threshold_vault(2, 3));
    let edits: Vec<(&str, &Vault, Edit)> = vec![
        (
            "threshold 0",
            &vault,
            Box::new(|t| {
                t.insert("threshold".into(), 0.into());
            }),
        ),
        (
            "threshold above n",
            &vault,
            Box::new(|t| {
                t.insert("threshold".into(), 3.into());
            }),
        ),
        (
            "a share with k = 1",
            &vault,
            Box::new(|t| {
                let mut key = entry(t, "keys", 0);
                key.insert("share".into(), 1.into());
                set_entry(t, "keys", 0, key);
            }),
        ),
        (
            "a repeated share",
            &threshold,
            Box::new(|t| {
                let mut key = entry(t, "keys", 1);
                key.insert("share".into(), 1.into());
                set_entry(t, "keys", 1, key);
            }),
        ),
        (
            "share 0 with k = 2",
            &threshold,
            Box::new(|t| {
                let mut key = entry(t, "keys", 1);
                key.insert("share".into(), 0.into());
                set_entry(t, "keys", 1, key);
            }),
        ),
        (
            "a migrated entry with k = 2",
            &threshold,
            Box::new(|t| {
                let mut key = entry(t, "keys", 1);
                key.insert("kind".into(), "fido2-hmac-v2".into());
                set_entry(t, "keys", 1, key);
            }),
        ),
        (
            "a short salt",
            &vault,
            Box::new(|t| {
                for index in 0..2 {
                    let mut key = entry(t, "keys", index);
                    key.insert("salt".into(), b64(&[7; 31]));
                    set_entry(t, "keys", index, key);
                }
            }),
        ),
        (
            "a short AAGUID",
            &vault,
            Box::new(|t| {
                let mut key = entry(t, "keys", 0);
                key.insert("aaguid".into(), b64(&[1; 15]));
                set_entry(t, "keys", 0, key);
            }),
        ),
        (
            "half a pending pair",
            &vault,
            Box::new(|t| {
                let mut secret = entry(t, "secrets", 0);
                secret.insert("pending_nonce".into(), b64(&[1; 24]));
                set_entry(t, "secrets", 0, secret);
            }),
        ),
        (
            "a short tag",
            &vault,
            Box::new(|t| {
                t.insert("tag".into(), b64(&[1; 31]));
            }),
        ),
        (
            "a bad meta key",
            &vault,
            Box::new(|t| {
                let mut meta = toml::Table::new();
                meta.insert("Bad Key".into(), "x".into());
                t.insert("meta".into(), meta.into());
            }),
        ),
        (
            "an unknown AEAD",
            &vault,
            Box::new(|t| {
                t.insert("aead".into(), "aes-256-gcm".into());
            }),
        ),
        (
            "an unknown kind",
            &vault,
            Box::new(|t| {
                let mut key = entry(t, "keys", 0);
                key.insert("kind".into(), "tpm".into());
                set_entry(t, "keys", 0, key);
            }),
        ),
        (
            "an unknown field",
            &vault,
            Box::new(|t| {
                t.insert("extra".into(), 1.into());
            }),
        ),
    ];
    for vault in [&vault, &threshold] {
        assert!(parse(&edited(vault, |_| {})).is_ok());
    }
    for (what, vault, edit) in edits {
        assert!(
            parse(&edited(vault, |t| edit(t))).is_err(),
            "{what} was accepted"
        );
    }
}

#[test]
fn an_unknown_algorithm_asks_for_an_update() {
    let text = edited(&one_key_vault(b"a"), |t| {
        t.insert("kdf".into(), "argon2id".into());
    });
    let error = error_of(parse(&text));
    assert!(error.contains("Update fido2kpxc"), "{error}");
}

/// A version 1 vault holding `hunter2`, sealed for `old` exactly as fido2kpxc 0.1 wrote it.
fn version_1_text(old: &Unlock) -> String {
    let key = [5; 32];
    let b = |bytes: &[u8]| STANDARD.encode(bytes);
    let seal = |with: &[u8; 32], msg: &[u8], aad: &[u8], n: [u8; 24]| {
        crypto::cipher(with)
            .encrypt(&XNonce::from(n), Payload { msg, aad })
            .unwrap()
    };
    format!(
        "version = 1\nsalt = \"{}\"\nnonce = \"{}\"\nciphertext = \"{}\"\n\n[[keys]]\nlabel = \"primary\"\ncred_id = \"{}\"\nnonce = \"{}\"\nwrapped_key = \"{}\"\n",
        b(&[7; 32]),
        b(&[1; 24]),
        b(&seal(&key, b"hunter2", b"fido2kpxc-vault-v1", [1; 24])),
        b(&old.cred_id),
        b(&[2; 24]),
        b(&seal(&old.output, &key, &old.cred_id, [2; 24])),
    )
}

#[test]
fn version_1_vault_opens_as_the_catch_all_and_saves_as_version_2() {
    let old = unlock(1, 10);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    std::fs::write(&path, version_1_text(&old)).unwrap();
    Vault::load_legacy(APP, &path)
        .unwrap()
        .save(&path, false)
        .unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .starts_with("version = 2")
    );
    assert_eq!(
        open(&Vault::load_legacy(APP, &path).unwrap(), old, "any.kdbx"),
        b"hunter2"
    );
}

#[test]
fn load_refuses_older_vaults_and_names_the_fix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    for text in [version_1_text(&unlock(1, 10)), FIXTURE.to_owned()] {
        std::fs::write(&path, text).unwrap();
        let error = error_of(Vault::load(APP, &path));
        assert!(error.contains("from an older version"), "{error}");
    }
}

#[test]
fn the_first_change_moves_a_v2_vault_to_v3() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    std::fs::write(&path, FIXTURE).unwrap();
    let [first, second] = fixture_keys();
    let mut vault = Vault::load_legacy(APP, &path).unwrap();
    vault
        .set_secret(std::slice::from_ref(&first), "new.kdbx", b"new")
        .unwrap();
    vault.save(&path, false).unwrap();
    let vault = Vault::load(APP, &path).unwrap();
    assert_eq!(vault.generation(), 1);
    let kinds: Vec<KeyKind> = vault.keys().iter().map(|k| k.kind).collect();
    assert_eq!(kinds, [KeyKind::Fido2Hmac, KeyKind::Fido2HmacV2]);
    for key in [first.clone(), second.clone()] {
        assert_eq!(open(&vault, key.clone(), "home.kdbx"), b"fixture-any");
        assert_eq!(open(&vault, key.clone(), "work.kdbx"), b"fixture-work");
        assert_eq!(open(&vault, key, "new.kdbx"), b"new");
    }
    let mut vault = vault;
    vault.upgrade(&[second]).unwrap();
    let kinds: Vec<KeyKind> = vault.keys().iter().map(|k| k.kind).collect();
    assert_eq!(kinds, [KeyKind::Fido2Hmac, KeyKind::Fido2Hmac]);
}

#[test]
fn create_refuses_to_replace_an_existing_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    two_key_vault(b"first").save(&path, true).unwrap();
    assert!(two_key_vault(b"second").save(&path, true).is_err());
    assert_eq!(
        open(&Vault::load(APP, &path).unwrap(), unlock(1, 10), "pdb.kdbx"),
        b"first"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn create_makes_a_missing_vault_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new/vault.toml");
    two_key_vault(b"hunter2").save(&path, true).unwrap();
    assert_eq!(
        open(&Vault::load(APP, &path).unwrap(), unlock(1, 10), "pdb.kdbx"),
        b"hunter2"
    );
}

#[test]
fn create_never_makes_a_missing_parent_folder() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing/fido2kpxc/vault.toml");
    assert!(two_key_vault(b"hunter2").save(&path, true).is_err());
    assert!(!dir.path().join("missing").exists());
}

#[test]
fn check_names_the_key_and_opens_every_password() {
    let mut vault = two_key_vault(b"hunter2");
    vault
        .set_secret(&[unlock(1, 10)], "pdb.kdbx", b"other")
        .unwrap();
    let check = vault.check(&[unlock(2, 20)]).unwrap();
    assert_eq!(check.labels, ["backup"]);
    assert_eq!(check.opened, [ANY, "pdb.kdbx"]);
    assert!(check.failed.is_empty());
}

#[test]
fn check_lists_a_password_that_fails_to_open_in_a_v2_vault() {
    let mut vault = Vault::parse(APP, FIXTURE, true).unwrap();
    vault.secrets[1].current.ciphertext[0] ^= 1;
    let check = vault.check(&[unlock(1, 10)]).unwrap();
    assert_eq!(check.labels, ["primary"]);
    assert_eq!(check.opened, [ANY]);
    assert_eq!(check.failed, ["work.kdbx"]);
}

#[test]
fn check_refuses_a_key_that_is_not_enrolled() {
    let vault = two_key_vault(b"hunter2");
    assert!(vault.check(&[unlock(3, 30)]).is_err());
}

#[test]
fn a_vault_from_a_newer_version_asks_for_an_update() {
    let error = error_of(parse("version = 7\n"));
    assert!(
        error.contains("from a newer fido2kpxc. Update fido2kpxc."),
        "{error}"
    );
}

#[test]
fn parsing_an_invalid_vault_fails() {
    let text = "version = 2\nsalt = \"\"\nkeys = []\nsecrets = []\n";
    assert!(Vault::parse(APP, text, true).is_err());
}

#[test]
fn duplicate_labels_are_refused() {
    let text = two_key_vault(b"pw")
        .to_text()
        .unwrap()
        .replace("\"backup\"", "\"primary\"");
    assert!(parse(&text).is_err());
}

#[test]
fn duplicate_credential_ids_are_refused() {
    // Two entries for the same key, as a hand edit could leave.
    let text = two_key_vault(b"pw").to_text().unwrap();
    let (id1, id2) = (STANDARD.encode([1u8; 16]), STANDARD.encode([2u8; 16]));
    assert!(parse(&text.replace(&id2, &id1)).is_err());
}

#[test]
fn a_vault_above_one_mib_is_refused_before_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    std::fs::write(&path, vec![b'#'; MAX_VAULT_BYTES as usize + 1]).unwrap();
    assert!(Vault::load(APP, &path).is_err());
}

#[test]
fn a_save_after_another_writers_save_fails_and_keeps_their_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    two_key_vault(b"old").save(&path, true).unwrap();
    let mut mine = Vault::load(APP, &path).unwrap();
    let mut theirs = Vault::load(APP, &path).unwrap();
    theirs.remove_keys(&["backup"], &[unlock(1, 10)]).unwrap();
    theirs.save(&path, false).unwrap();
    mine.set_secret(&[unlock(2, 20)], "new.kdbx", b"new")
        .unwrap();
    assert!(mine.save(&path, false).is_err());
    // The removed backup key still opens nothing.
    assert!(
        Vault::load(APP, &path)
            .unwrap()
            .open(&[unlock(2, 20)], None)
            .is_err()
    );
}

#[test]
fn the_same_value_saves_twice() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    two_key_vault(b"pw").save(&path, true).unwrap();
    let mut vault = Vault::load(APP, &path).unwrap();
    vault.set_secret(&[unlock(1, 10)], "a.kdbx", b"a").unwrap();
    vault.save(&path, false).unwrap();
    vault.set_secret(&[unlock(1, 10)], "b.kdbx", b"b").unwrap();
    vault.save(&path, false).unwrap();
    assert_eq!(
        Vault::load(APP, &path).unwrap().names(),
        ["*", "a.kdbx", "b.kdbx"]
    );
}

#[test]
fn a_saved_vault_with_a_newer_version_asks_for_an_update() {
    let text = two_key_vault(b"hunter2")
        .to_text()
        .unwrap()
        .replace("version = 3", "version = 7");
    let error = error_of(parse(&text));
    assert!(error.contains("Update fido2kpxc"), "{error}");
}

const FIXTURE: &str = include_str!("fixtures/v2-fido2kpxc-0.2.2.toml");

/// The keys and secrets the fixture was written with, by fido2kpxc v0.2.2's own vault code.
fn fixture_keys() -> [Unlock; 2] {
    [unlock(1, 10), unlock(2, 20)]
}

#[test]
fn a_fido2kpxc_0_2_2_vault_keeps_its_bytes() {
    let vault = Vault::parse(APP, FIXTURE, true).unwrap();
    assert_eq!(vault.to_text().unwrap(), FIXTURE);
}

#[test]
fn a_fido2kpxc_0_2_2_vault_opens_with_each_key() {
    let vault = Vault::parse(APP, FIXTURE, true).unwrap();
    for key in fixture_keys() {
        assert_eq!(open(&vault, key.clone(), "home.kdbx"), b"fixture-any");
        assert_eq!(open(&vault, key, "work.kdbx"), b"fixture-work");
    }
}

#[test]
fn a_fido2kpxc_0_2_2_vault_still_opens_after_a_save() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    std::fs::write(&path, FIXTURE).unwrap();
    Vault::load_legacy(APP, &path)
        .unwrap()
        .save(&path, false)
        .unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), FIXTURE);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    let saved = Vault::load_legacy(APP, &path).unwrap();
    for key in fixture_keys() {
        assert_eq!(open(&saved, key.clone(), "home.kdbx"), b"fixture-any");
        assert_eq!(open(&saved, key, "work.kdbx"), b"fixture-work");
    }
}

#[test]
fn another_app_cannot_open_a_fido2kpxc_vault() {
    let vault = Vault::parse(App::new("fido2tomb"), FIXTURE, true).unwrap();
    for key in fixture_keys() {
        for name in [None, Some("work.kdbx")] {
            let error = error_of(vault.open(std::slice::from_ref(&key), name));
            assert!(error.contains("failed authentication"), "{error}");
        }
    }
}

#[test]
fn another_app_cannot_open_a_migrated_version_1_vault() {
    let old = unlock(1, 10);
    let vault = Vault::parse(App::new("fido2tomb"), &version_1_text(&old), true).unwrap();
    let error = error_of(vault.open(&[old], None));
    assert!(error.contains("failed authentication"), "{error}");
}

#[test]
fn fido2kpxc_keeps_its_aad_bytes() {
    assert_eq!(legacy_secret_aad(APP, ANY), b"fido2kpxc-vault-v1");
    assert_eq!(
        legacy_secret_aad(APP, "pdb.kdbx"),
        b"fido2kpxc-secret:pdb.kdbx"
    );
    assert_eq!(
        legacy_secret_aad(App::new("fido2tomb"), ANY),
        b"fido2tomb-vault-v1"
    );
}
