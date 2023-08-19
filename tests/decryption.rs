mod tests {
    mod decryption {
        #[test]
        fn simple_decrypt() -> ubiq::result::Result<()> {
            let creds = ubiq::credentials::Credentials::new(None, None)?;

            let pt = b"abc";
            let ct = ubiq::encryption::encrypt(&creds, &pt[..])?;
            let rec = ubiq::decryption::decrypt(&creds, &ct)?;

            assert!(pt[..] == rec, "{}", "recovered plaintext does not match");

            Ok(())
        }
    }
}
