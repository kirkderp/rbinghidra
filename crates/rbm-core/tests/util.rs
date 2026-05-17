use rbm_core::util::int_convert;

#[test]
fn decimal_convert() {
    let r = int_convert("255").unwrap();
    assert_eq!(r.decimal, "255");
    assert_eq!(r.hex, "0xff");
    assert_eq!(r.binary, "0b11111111");
    assert_eq!(r.octal, "0o377");
}

#[test]
fn hex_convert() {
    let r = int_convert("0xFF").unwrap();
    assert_eq!(r.decimal, "255");
    assert_eq!(r.hex, "0xff");
}

#[test]
fn binary_convert() {
    let r = int_convert("0b1010").unwrap();
    assert_eq!(r.decimal, "10");
    assert_eq!(r.hex, "0xa");
}

#[test]
fn octal_convert() {
    let r = int_convert("0o755").unwrap();
    assert_eq!(r.decimal, "493");
    assert_eq!(r.octal, "0o755");
}

#[test]
fn ascii_printable() {
    let r = int_convert("0x41424344").unwrap();
    assert_eq!(r.ascii.as_deref(), Some("ABCD"));
}

#[test]
fn ascii_non_printable() {
    let r = int_convert("0x00010203").unwrap();
    assert!(r.ascii.is_none());
}

#[test]
fn empty_input() {
    assert!(int_convert("").is_err());
}

#[test]
fn invalid_hex() {
    assert!(int_convert("0xZZ").is_err());
}
