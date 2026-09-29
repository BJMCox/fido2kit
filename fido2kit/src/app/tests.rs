use super::*;

#[test]
fn a_lowercase_name_with_digits_is_accepted() {
    assert_eq!(App::new("fido2kpxc").name(), "fido2kpxc");
}

#[test]
fn names_outside_lowercase_letters_and_digits_are_refused() {
    for bad in ["", "p-secret:q", "a/b", "A", "fido2 kpxc", "."] {
        assert!(
            std::panic::catch_unwind(|| App::new(bad)).is_err(),
            "{bad:?} was accepted"
        );
    }
}
