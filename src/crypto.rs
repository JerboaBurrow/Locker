use openssl::
{
    rsa::{Rsa, Padding},
    pkey::Private,
    sha::Sha256, symm::Cipher
};

use crate::
{
    util::{read_file_utf8, dump_bytes, write_file},
    error::RSAError
};

pub fn generate_key(path: &str, pass: Option<String>) -> Result<(), RSAError>
{
    let rsa = match Rsa::generate(4096)
    {
        Ok(k) => k,
        Err(e) => { return Err(RSAError { why: format!("While generating RSA key: {}", e)}); }
    };

    let pass = match pass 
    {
        Some(s) => s,
        None => 
        {
            rpassword::prompt_password
            (
                format!("Passphrase for new key: ")
            ).unwrap()
        }
    };

    let pem = match rsa.private_key_to_pem_passphrase(Cipher::aes_256_cbc(), pass.as_bytes())
    {
        Ok(pem) => pem,
        Err(e) => { return Err(RSAError { why: format!("While building encrypted PEM: {}", e) }); }
    };

    write_file(path, &pem);

    Ok(())
}

pub fn build_rsa(path: &str, pass: &str) -> Result<Rsa<Private>, RSAError>
{
    let pem = match read_file_utf8(path)
    {
        Ok(p) => p,
        Err(e) => 
        {
            return Err
            (
                RSAError 
                { 
                    why: format!("PEM file, {}, read error: {}",e.file, e.why)
                }
            )
        }
    };

    let rsa_input = Rsa::private_key_from_pem_passphrase
    (
        pem.as_bytes(),
        pass.as_bytes()
    );

    match rsa_input
    {
        Err(why) => 
        {
            Err(RSAError {why: format!("Incorrect password for PEM {}?\nStack: \n{}", path, why) })
        },
        Ok(_) => {Ok(rsa_input.unwrap())}
    }
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