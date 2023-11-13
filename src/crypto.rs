use openssl::
{
    rsa::{Rsa, Padding},
    pkey::Private,
    sha::Sha256
};

use crate::util::{read_file_utf8, dump_bytes};

pub fn build_rsa(path: &str, pass: &str) -> Rsa<Private>
{
    let pem = read_file_utf8(path);

    let rsa_input = Rsa::private_key_from_pem_passphrase
    (
        pem.as_bytes(),
        pass.as_bytes()
    );

    match rsa_input
    {
        Err(why) => panic!("when obtaining private key from pem file, {}, {}", path, why),
        Ok(_) => ()
    }

    rsa_input.unwrap()

}

/*
    Encrypt to rsa's public key
*/
pub fn encrypt(rsa: Rsa<Private>, data: &[u8]) -> Vec<u8>
{
    let mut buf = vec![0; rsa.size() as usize];
    let _len = rsa.public_encrypt(data, &mut buf, Padding::PKCS1).unwrap();
    buf
}

/*
    Decrypt data previously encrypted t rsa's public key
        Padding will leave null bytes, they can be trimmed 
        downstream, e.g. after parsing to a String: string.trim_matches(char::from(0))
*/
pub fn decrypt(rsa: Rsa<Private>, data: &[u8]) -> Vec<u8> 
{
    let mut buf = vec![0; rsa.size() as usize];
    let _len = rsa.private_decrypt(data, &mut buf, Padding::PKCS1).unwrap();
    buf
}

pub fn hash(v: &str) -> [u8; 32]
{
    let mut sha = Sha256::new();
    sha.update(v.as_bytes());
    sha.finish()
}

pub fn decrypt_string(data: Vec<u8>, rsa: Rsa<Private>) -> String
{
    let result = decrypt(rsa, &data);
    match std::str::from_utf8(&result)
    {
        Err(_e) => 
        {
            dump_bytes(&result)
        }
        Ok(str) => str.to_string().trim_matches(char::from(0)).to_string()
    }
}