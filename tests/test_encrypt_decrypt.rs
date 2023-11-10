#[cfg(test)]
mod test_encrypt_decrypt
{
    use locker::crypto::{encrypt, decrypt, build_rsa};

    const TEST_STRING: &str = "a secret message";

    #[test]
    fn encrypt_decrypt()
    {
        let rsa = build_rsa("tests/donotuse.pem", "password");
        let enc_result = encrypt(rsa.clone(), TEST_STRING.as_bytes());
        let dec_result = decrypt(rsa, &enc_result);
        // 0's will be padded to dec_result
        assert_eq!(&dec_result[0..TEST_STRING.len()], TEST_STRING.as_bytes());
    }
}