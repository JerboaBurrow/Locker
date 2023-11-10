use openssl::
{
    rsa::{Rsa, Padding},
    pkey::{Private},
};

use crate::util::read_file_utf8;

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

pub fn encrypt(rsa: Rsa<Private>, data: &[u8]) -> Vec<u8>
{
    let mut buf = vec![0; rsa.size() as usize];
    let _len = rsa.public_encrypt(data, &mut buf, Padding::PKCS1).unwrap();
    buf
}

pub fn decrypt(rsa: Rsa<Private>, data: &[u8]) -> Vec<u8> 
{
    let mut buf = vec![0; rsa.size() as usize];
    let _len = rsa.private_decrypt(data, &mut buf, Padding::PKCS1).unwrap();
    buf
}