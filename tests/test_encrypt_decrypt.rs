mod common;

#[cfg(test)]
mod test_encrypt_decrypt
{
    use crate::common::*;
    use locker::crypto::{encrypt, decrypt, build_rsa};
    use locker::util::read_file_raw;

    #[test]
    fn encrypt_decrypt()
    {
        let rsa = build_rsa(PEM_PATH, PEM_PASSWORD);
        let enc_result = encrypt(rsa.clone(), TEST_STRING.as_bytes());
        let dec_result = decrypt(rsa, &enc_result);
        // 0's will be padded to dec_result
        assert_eq!(&dec_result[0..TEST_STRING.len()], TEST_STRING.as_bytes());
    }

    #[test]
    fn cipher_text_is_different()
    {
        let rsa = build_rsa(PEM_PATH, PEM_PASSWORD);
        let enc_result_a = encrypt(rsa.clone(), TEST_STRING.as_bytes());
        let enc_result_b = encrypt(rsa.clone(), TEST_STRING.as_bytes());
        assert_ne!(enc_result_a, enc_result_b);

        let dec_result_a = decrypt(rsa.clone(), &enc_result_a);
        let dec_result_b = decrypt(rsa.clone(), &enc_result_b);

        assert_eq!(dec_result_a, dec_result_b);

        assert_eq!(&dec_result_a[0..TEST_STRING.len()], TEST_STRING.as_bytes());
        assert_eq!(&dec_result_b[0..TEST_STRING.len()], TEST_STRING.as_bytes());
    }

    #[test]
    fn test_decrypt_file()
    {
        let rsa = build_rsa(PEM_PATH, PEM_PASSWORD);
        let data = read_file_raw(TEST_ENCRYPTED_FILE);
        let result = decrypt(rsa, &data);

        assert_eq!(&result[0..3], TEST_ENCRYPTED_FILE_PLAIN.as_bytes());
    }
}