mod tests {
    mod credentials {
        #[test]
        fn default_new() {
            let r = ubiq::credentials::Credentials::new(None, None);
            assert!(r.is_ok(), "{}", r.unwrap_err().to_string());
        }

        #[test]
        fn simple_create() {
            ubiq::credentials::Credentials::create(
                "abc".to_string(),
                "xyz".to_string(),
                "123".to_string(),
                None,
            );
        }
    }
}
