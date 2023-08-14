mod tests {
    mod credentials {
        #[test]
        fn default_new() {
            let r = ubiq::credentials::Credentials::new(None, None);
            unsafe {
                assert!(r.is_ok(), "{}", r.unwrap_err_unchecked().to_string());
            }
        }

        #[test]
        fn simple_create() {
            let r = ubiq::credentials::Credentials::create(
                "abc".to_string(),
                "xyz".to_string(),
                "123".to_string(),
                None,
            );
            unsafe {
                assert!(r.is_ok(), "{}", r.unwrap_err_unchecked().to_string());
            }
        }
    }
}
