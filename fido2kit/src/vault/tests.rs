use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

const APP: App = App::new("fido2kpxc");

fn unlock(id: u8, output: u8) -> Unlock {
    Unlock {
        cred_id: vec![id; 16],
        output: Zeroizing::new([output; 32]),
    }
}

fn two_key_vault(secret: &[u8]) -> Vault {
    let mut vault = Vault::create(APP, [7; 32], "primary", &unlock(1, 10), ANY, secret).unwrap();
    vault
        .add_key(&unlock(1, 10), "backup", &unlock(2, 20))
        .unwrap();
    vault
}

fn open(vault: &Vault, key: &Unlock, database: &str) -> Vec<u8> {
    vault.open(key, Some(database)).unwrap().to_vec()
}

#[test]
fn either_key_opens_the_vault_after_a_save_and_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    two_key_vault(b"hunter2").save(&path, true).unwrap();
    let vault = Vault::load(APP, &path).unwrap();
    assert_eq!(vault.salt(), [7; 32]);
    assert_eq!(open(&vault, &unlock(1, 10), "pdb.kdbx"), b"hunter2");
    assert_eq!(open(&vault, &unlock(2, 20), "pdb.kdbx"), b"hunter2");
}

#[test]
fn exact_database_name_beats_the_catch_all() {
    let mut vault = two_key_vault(b"default");
    vault
        .set_secret(&unlock(1, 10), "work.kdbx", b"work")
        .unwrap();
    assert_eq!(open(&vault, &unlock(2, 20), "work.kdbx"), b"work");
    assert_eq!(open(&vault, &unlock(2, 20), "home.kdbx"), b"default");
}

#[test]
fn unknown_database_without_a_catch_all_has_no_secret() {
    let vault = Vault::create(
        APP,
        [7; 32],
        "primary",
        &unlock(1, 10),
        "work.kdbx",
        b"work",
    )
    .unwrap();
    assert!(!vault.has_secret_for(Some("home.kdbx")));
    assert!(vault.open(&unlock(1, 10), Some("home.kdbx")).is_err());
    assert_eq!(open(&vault, &unlock(1, 10), "work.kdbx"), b"work");
}

#[test]
fn set_secret_keeps_every_key_working() {
    let mut vault = two_key_vault(b"old");
    vault.set_secret(&unlock(1, 10), ANY, b"new").unwrap();
    assert_eq!(open(&vault, &unlock(2, 20), "pdb.kdbx"), b"new");
    assert_eq!(vault.names(), vec![ANY]);
}

#[test]
fn remove_secret_falls_back_to_the_catch_all() {
    let mut vault = two_key_vault(b"default");
    vault
        .set_secret(&unlock(1, 10), "work.kdbx", b"work")
        .unwrap();
    vault.remove_secret("work.kdbx").unwrap();
    assert_eq!(open(&vault, &unlock(1, 10), "work.kdbx"), b"default");
    assert!(vault.remove_secret(ANY).is_err());
}

#[test]
fn remove_key_keeps_the_other_keys_working() {
    let mut vault = two_key_vault(b"hunter2");
    vault
        .set_secret(&unlock(1, 10), "work.kdbx", b"work")
        .unwrap();
    vault
        .add_key(&unlock(1, 10), "third", &unlock(3, 30))
        .unwrap();
    vault
        .remove_keys(&["backup"], &[unlock(1, 10), unlock(3, 30)])
        .unwrap();
    assert!(vault.open(&unlock(2, 20), None).is_err());
    assert_eq!(open(&vault, &unlock(1, 10), "pdb.kdbx"), b"hunter2");
    assert_eq!(open(&vault, &unlock(3, 30), "work.kdbx"), b"work");
}

#[test]
fn removed_key_cannot_read_vaults_written_after_removal() {
    let mut vault = two_key_vault(b"hunter2");
    let old_copy = Vault::parse(APP, &toml::to_string(&vault).unwrap()).unwrap();
    vault.remove_keys(&["backup"], &[unlock(1, 10)]).unwrap();
    vault.set_secret(&unlock(1, 10), ANY, b"rotated").unwrap();
    // The removed key still opens its old copy, so it knows the old data key.
    let old_key = old_copy.unwrap(&unlock(2, 20)).unwrap();
    let secret = &vault.secrets[0];
    let payload = Payload {
        msg: &secret.ciphertext,
        aad: &secret_aad(APP, ANY),
    };
    assert!(
        cipher(&old_key)
            .decrypt(&nonce(&secret.nonce), payload)
            .is_err()
    );
}

#[test]
fn remove_key_refuses_the_last_key() {
    let mut vault =
        Vault::create(APP, [7; 32], "primary", &unlock(1, 10), ANY, b"hunter2").unwrap();
    assert!(vault.remove_keys(&["primary"], &[]).is_err());
    assert_eq!(open(&vault, &unlock(1, 10), "pdb.kdbx"), b"hunter2");
}

#[test]
fn two_lost_keys_are_removed_at_once_with_only_the_kept_keys() {
    let mut vault = two_key_vault(b"hunter2");
    for (label, id) in [("third", 3), ("fourth", 4)] {
        vault
            .add_key(&unlock(1, 10), label, &unlock(id, id * 10))
            .unwrap();
    }
    vault
        .remove_keys(&["backup", "third"], &[unlock(1, 10), unlock(4, 40)])
        .unwrap();
    assert!(vault.open(&unlock(2, 20), None).is_err());
    assert!(vault.open(&unlock(3, 30), None).is_err());
    assert_eq!(open(&vault, &unlock(1, 10), "pdb.kdbx"), b"hunter2");
    assert_eq!(open(&vault, &unlock(4, 40), "pdb.kdbx"), b"hunter2");
    assert_eq!(vault.kept_keys(&[]).unwrap().len(), 2);
}

#[test]
fn removing_every_key_fails_and_changes_nothing() {
    let mut vault = two_key_vault(b"hunter2");
    assert!(vault.remove_keys(&["primary", "backup"], &[]).is_err());
    assert_eq!(open(&vault, &unlock(2, 20), "pdb.kdbx"), b"hunter2");
}

#[test]
fn an_unknown_label_fails_and_changes_nothing() {
    let mut vault = two_key_vault(b"hunter2");
    assert!(
        vault
            .remove_keys(&["backup", "spare"], &[unlock(1, 10)])
            .is_err()
    );
    assert_eq!(open(&vault, &unlock(2, 20), "pdb.kdbx"), b"hunter2");
}

#[test]
fn kept_keys_lists_the_keys_that_need_a_touch() {
    let mut vault = two_key_vault(b"hunter2");
    vault
        .add_key(&unlock(1, 10), "third", &unlock(3, 30))
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
fn tampered_ciphertext_fails_to_open() {
    let mut vault = two_key_vault(b"hunter2");
    vault.secrets[0].ciphertext[0] ^= 1;
    assert!(vault.open(&unlock(1, 10), None).is_err());
}

#[test]
fn swapped_database_names_fail_to_open() {
    let mut vault = two_key_vault(b"home");
    vault
        .set_secret(&unlock(1, 10), "work.kdbx", b"work")
        .unwrap();
    let first = vault.secrets[0].name.clone();
    vault.secrets[0].name = vault.secrets[1].name.clone();
    vault.secrets[1].name = first;
    assert!(vault.open(&unlock(1, 10), Some("work.kdbx")).is_err());
}

#[test]
fn swapped_cred_ids_fail_to_unwrap() {
    // Both keys share one output, so only the cred_id binding can reject the swap.
    let mut vault =
        Vault::create(APP, [7; 32], "primary", &unlock(1, 10), ANY, b"hunter2").unwrap();
    vault
        .add_key(&unlock(1, 10), "backup", &unlock(2, 10))
        .unwrap();
    let first = vault.keys[0].cred_id.clone();
    vault.keys[0].cred_id = vault.keys[1].cred_id.clone();
    vault.keys[1].cred_id = first;
    assert!(vault.open(&unlock(2, 10), None).is_err());
}

/// A version 1 vault holding `hunter2`, sealed for `old` exactly as fido2kpxc 0.1 wrote it.
fn version_1_text(old: &Unlock) -> String {
    let key = [5; 32];
    let b = |bytes: &[u8]| STANDARD.encode(bytes);
    let seal = |with: &[u8; 32], msg: &[u8], aad: &[u8], n: [u8; 24]| {
        cipher(with)
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
    Vault::load(APP, &path).unwrap().save(&path, false).unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .starts_with("version = 2")
    );
    assert_eq!(
        open(&Vault::load(APP, &path).unwrap(), &old, "any.kdbx"),
        b"hunter2"
    );
}

#[test]
fn create_refuses_to_replace_an_existing_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    two_key_vault(b"first").save(&path, true).unwrap();
    assert!(two_key_vault(b"second").save(&path, true).is_err());
    assert_eq!(
        open(
            &Vault::load(APP, &path).unwrap(),
            &unlock(1, 10),
            "pdb.kdbx"
        ),
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
        open(
            &Vault::load(APP, &path).unwrap(),
            &unlock(1, 10),
            "pdb.kdbx"
        ),
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
        .set_secret(&unlock(1, 10), "pdb.kdbx", b"other")
        .unwrap();
    let check = vault.check(&unlock(2, 20)).unwrap();
    assert_eq!(check.label, "backup");
    assert_eq!(check.opened, [ANY, "pdb.kdbx"]);
    assert!(check.failed.is_empty());
}

#[test]
fn check_lists_a_password_that_fails_to_open() {
    let mut vault = two_key_vault(b"hunter2");
    vault
        .set_secret(&unlock(1, 10), "pdb.kdbx", b"other")
        .unwrap();
    vault.secrets[1].ciphertext[0] ^= 1;
    let check = vault.check(&unlock(1, 10)).unwrap();
    assert_eq!(check.label, "primary");
    assert_eq!(check.opened, [ANY]);
    assert_eq!(check.failed, ["pdb.kdbx"]);
}

#[test]
fn check_refuses_a_key_that_is_not_enrolled() {
    let vault = two_key_vault(b"hunter2");
    assert!(vault.check(&unlock(3, 30)).is_err());
}

#[test]
fn a_vault_from_a_newer_version_asks_for_an_update() {
    let error = Vault::parse(APP, "version = 3\n").err().unwrap();
    assert!(
        format!("{error:#}").contains("from a newer fido2kpxc. Update fido2kpxc."),
        "{error:#}"
    );
}

#[test]
fn parsing_an_invalid_vault_fails() {
    let text = "version = 2\nsalt = \"\"\nkeys = []\nsecrets = []\n";
    assert!(Vault::parse(APP, text).is_err());
}

#[test]
fn duplicate_labels_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    two_key_vault(b"pw").save(&path, true).unwrap();
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\"backup\"", "\"primary\"");
    std::fs::write(&path, text).unwrap();
    assert!(Vault::load(APP, &path).is_err());
}

#[test]
fn duplicate_credential_ids_are_refused() {
    // Two entries for the same key, as a hand edit could leave.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    two_key_vault(b"pw").save(&path, true).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    let (id1, id2) = (STANDARD.encode([1u8; 16]), STANDARD.encode([2u8; 16]));
    std::fs::write(&path, text.replace(&id2, &id1)).unwrap();
    assert!(Vault::load(APP, &path).is_err());
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
    mine.set_secret(&unlock(2, 20), "new.kdbx", b"new").unwrap();
    assert!(mine.save(&path, false).is_err());
    // The removed backup key still opens nothing.
    assert!(
        Vault::load(APP, &path)
            .unwrap()
            .open(&unlock(2, 20), None)
            .is_err()
    );
}

#[test]
fn the_same_value_saves_twice() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    two_key_vault(b"pw").save(&path, true).unwrap();
    let mut vault = Vault::load(APP, &path).unwrap();
    vault.set_secret(&unlock(1, 10), "a.kdbx", b"a").unwrap();
    vault.save(&path, false).unwrap();
    vault.set_secret(&unlock(1, 10), "b.kdbx", b"b").unwrap();
    vault.save(&path, false).unwrap();
    assert_eq!(
        Vault::load(APP, &path).unwrap().names(),
        ["*", "a.kdbx", "b.kdbx"]
    );
}

#[test]
fn a_saved_vault_with_a_newer_version_asks_for_an_update() {
    let text = toml::to_string(&two_key_vault(b"hunter2"))
        .unwrap()
        .replace("version = 2", "version = 7");
    let error = Vault::parse(APP, &text).err().unwrap();
    assert!(
        format!("{error:#}").contains("Update fido2kpxc"),
        "{error:#}"
    );
}

const FIXTURE: &str = include_str!("fixtures/v2-fido2kpxc-0.2.2.toml");

/// The keys and secrets the fixture was written with, by fido2kpxc v0.2.2's own vault code.
fn fixture_keys() -> [Unlock; 2] {
    [unlock(1, 10), unlock(2, 20)]
}

#[test]
fn a_fido2kpxc_0_2_2_vault_keeps_its_bytes() {
    let vault = Vault::parse(APP, FIXTURE).unwrap();
    assert_eq!(toml::to_string(&vault).unwrap(), FIXTURE);
}

#[test]
fn a_fido2kpxc_0_2_2_vault_opens_with_each_key() {
    let vault = Vault::parse(APP, FIXTURE).unwrap();
    for key in fixture_keys() {
        assert_eq!(open(&vault, &key, "home.kdbx"), b"fixture-any");
        assert_eq!(open(&vault, &key, "work.kdbx"), b"fixture-work");
    }
}

#[test]
fn a_fido2kpxc_0_2_2_vault_still_opens_after_a_save() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    std::fs::write(&path, FIXTURE).unwrap();
    Vault::load(APP, &path).unwrap().save(&path, false).unwrap();
    let saved = Vault::load(APP, &path).unwrap();
    for key in fixture_keys() {
        assert_eq!(open(&saved, &key, "home.kdbx"), b"fixture-any");
        assert_eq!(open(&saved, &key, "work.kdbx"), b"fixture-work");
    }
}

#[test]
fn another_app_cannot_open_a_fido2kpxc_vault() {
    let vault = Vault::parse(App::new("fido2tomb"), FIXTURE).unwrap();
    for key in fixture_keys() {
        assert!(vault.open(&key, None).is_err());
        assert!(vault.open(&key, Some("work.kdbx")).is_err());
    }
}

#[test]
fn another_app_cannot_open_a_migrated_version_1_vault() {
    let old = unlock(1, 10);
    let vault = Vault::parse(App::new("fido2tomb"), &version_1_text(&old)).unwrap();
    assert!(vault.open(&old, None).is_err());
}

#[test]
fn fido2kpxc_keeps_its_aad_bytes() {
    assert_eq!(secret_aad(APP, ANY), b"fido2kpxc-vault-v1");
    assert_eq!(secret_aad(APP, "pdb.kdbx"), b"fido2kpxc-secret:pdb.kdbx");
    assert_eq!(
        secret_aad(App::new("fido2tomb"), ANY),
        b"fido2tomb-vault-v1"
    );
}
