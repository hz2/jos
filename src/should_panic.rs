use jos::serial_print;

#[test_case]
fn should_fail() {
    serial_print("should_fail::should_fail...\t");
    assert_eq!(0, 1);
}
