mod tests {
    mod credentials {
        #[test]
        fn simple_create() {
            let c = ubiq::credentials::Credentials::new(None, None);
            unsafe {
                assert!(
                    c.is_ok(),
                    "{}",
                    c.unwrap_err_unchecked().to_string()
                );
            }
        }
    }
}
