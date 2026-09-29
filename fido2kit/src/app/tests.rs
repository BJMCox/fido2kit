use super::*;

#[test]
fn a_lowercase_name_with_digits_is_accepted() {
    assert_eq!(App::new("fido2kpxc").name(), "fido2kpxc");
    assert_eq!(App::new("2").name(), "2");
}

#[test]
fn names_outside_lowercase_letters_and_digits_are_refused() {
    for bad in ["", "p-secret:q", "a/b", "A", "fido2 kpxc", ".", "é"] {
        assert!(
            std::panic::catch_unwind(|| App::new(bad)).is_err(),
            "{bad:?} was accepted"
        );
    }
}
