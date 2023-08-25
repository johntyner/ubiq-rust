mod tests {
    mod encryption {
        #[test]
        fn no_encryption() -> ubiq::result::Result<()> {
            let creds = ubiq::credentials::Credentials::new(None, None)?;
            let _ = ubiq::encryption::Encryption::new(&creds, 1)?;
            Ok(())
        }

        #[test]
        fn simple_encryption() -> ubiq::result::Result<()> {
            let creds = ubiq::credentials::Credentials::new(None, None)?;
            let _ = ubiq::encryption::encrypt(&creds, &vec![1, 2, 3][..])?;
            Ok(())
        }
    }
}
