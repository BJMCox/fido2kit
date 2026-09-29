use super::*;

#[test]
fn ctap_status_text_maps_to_ui_cases() {
    let map = |text: &str| classify(anyhow!("{text}"));
    assert!(matches!(map("FIDO device not found."), FidoError::NoDevice));
    assert!(matches!(
        map("0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid."),
        FidoError::WrongPin { .. }
    ));
    assert!(matches!(
        map("0x32 CTAP2_ERR_PIN_BLOCKED PIN Blocked."),
        FidoError::PinBlocked
    ));
    assert!(matches!(
        map("0x34 CTAP2_ERR_PIN_AUTH_BLOCKED PIN authentication, pinAuth, blocked."),
        FidoError::PinAuthBlocked
    ));
    assert!(matches!(
        map("0x2E CTAP2_ERR_NO_CREDENTIALS    No valid credentials provided."),
        FidoError::NotEnrolled
    ));
    assert!(matches!(
        map("0x3A CTAP2_ERR_ACTION_TIMEOUT Maximum time for user action expired."),
        FidoError::Timeout
    ));
    assert!(matches!(
        map("read err = something else"),
        FidoError::Other(_)
    ));
}

#[test]
fn an_excluded_credential_means_already_enrolled() {
    let error = classify(anyhow!(
        "0x19 CTAP2_ERR_CREDENTIAL_EXCLUDED Valid credential found in the exclude list."
    ));
    assert!(matches!(error, FidoError::AlreadyEnrolled));
}

#[test]
fn only_pin_errors_retry_the_pin() {
    let bad_pin = anyhow::Error::from(FidoError::WrongPin { retries: Some(2) });
    assert!(retry_pin(&bad_pin));
    for other in [
        FidoError::NotEnrolled,
        FidoError::PinBlocked,
        FidoError::PinAuthBlocked,
        FidoError::Timeout,
    ] {
        assert!(!retry_pin(&anyhow::Error::from(other)));
    }
    assert!(!retry_pin(&anyhow::anyhow!("The vault is gone")));
}

#[test]
fn a_missing_pin_retries_the_pin() {
    let map = |text: &str| classify(anyhow!("{text}"));
    assert!(matches!(
        map("0x36 CTAP2_ERR_PIN_REQUIRED  PIN is required for the selected operation."),
        FidoError::PinRequired
    ));
    assert!(matches!(
        map("CTAP2_ERR_PUAT_REQUIRED"),
        FidoError::PinRequired
    ));
    assert!(retry_pin(&anyhow::Error::new(FidoError::PinRequired)));
}

#[test]
fn a_pin_demand_on_a_silent_check_is_final() {
    let mapped = no_silent_check(FidoError::PinRequired);
    assert!(matches!(mapped, FidoError::Other(_)));
    assert!(mapped.to_string().contains("always-require-PIN setting"));
    assert!(!retry_pin(&anyhow::Error::new(mapped)));
    assert!(matches!(
        no_silent_check(FidoError::WrongPin { retries: Some(3) }),
        FidoError::WrongPin { retries: Some(3) }
    ));
    assert!(matches!(
        no_silent_check(FidoError::Timeout),
        FidoError::Timeout
    ));
}

#[test]
fn pins_are_normalized_to_nfc_and_keep_spaces() {
    assert_eq!(*nfc(" e\u{301} "), " \u{e9} ");
}

// A reallocation would leave a freed, unzeroized copy of the PIN behind.
#[test]
fn nfc_never_reallocates() {
    for pin in [
        "1234",
        "e\u{301}e\u{301}e\u{301}",
        "\u{1100}\u{1161}\u{11a8}",
        " x ",
    ] {
        let expected = String::with_capacity(3 * pin.len()).capacity();
        assert_eq!(nfc(pin).capacity(), expected, "{pin:?}");
    }
}

#[test]
fn keys_that_support_protocol_one_keep_it() {
    assert_eq!(pin_protocol(&[2, 1]), 1);
    assert_eq!(pin_protocol(&[2]), 2);
    assert_eq!(pin_protocol(&[]), 1);
}

#[test]
fn credential_lists_split_only_above_the_limits() {
    let (a, b, c) = (&[1u8; 16][..], &[2u8; 16][..], &[3u8; 80][..]);
    assert!(chunks(&[a, b], 2, 0).is_none());
    assert_eq!(chunks(&[a, b], 1, 0).unwrap(), vec![vec![a], vec![b]]);
    assert_eq!(chunks(&[a, c, b], 2, 64).unwrap(), vec![vec![a, b]]);
}

#[test]
fn argument_builders_carry_the_app_and_the_mode() {
    let app = App::new("fido2tomb");
    let made = make_args(app, &[0; 32], Some("1234"), &[&[1u8; 16][..]], None, true);
    assert_eq!(made.rpid, "fido2tomb");
    assert_eq!(made.pin, Some("1234"));
    assert_eq!(made.exclude_list, vec![vec![1u8; 16]]);
    assert!(made.user_entity.is_none());
    assert!(made.extensions.is_some());
    let plain = make_args(app, &[0; 32], None, &[], None, false);
    assert_eq!(plain.pin, None);
    assert_eq!(plain.uv, None);
    assert!(plain.extensions.is_none());

    let hmac = assert_args(app, &[0; 32], &[&[2u8; 16][..]], Some(("1234", &[9; 32])));
    assert_eq!(hmac.rpid, "fido2tomb");
    assert_eq!(hmac.pin, Some("1234"));
    assert!(hmac.up);
    assert_eq!(hmac.credential_ids, vec![vec![2u8; 16]]);
    let silent = assert_args(app, &[0; 32], &[&[2u8; 16][..]], None);
    assert_eq!(silent.pin, None);
    assert_eq!(silent.uv, None);
    assert!(!silent.up);
    assert!(silent.extensions.is_none());
}

#[test]
fn a_key_from_a_path_uses_that_path() {
    let Key(HidParam::Path(path)) = Key::from_path("DevSrvsID:4297189420".to_owned()) else {
        panic!("not a path");
    };
    assert_eq!(path, "DevSrvsID:4297189420");
}
