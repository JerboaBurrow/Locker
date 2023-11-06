use openssl::
{
    rsa::{Rsa, Padding},
    pkey::{PKey}
};

use std::io;

use crate::util::read_file;

pub fn encrypt(path: &str, data: String) -> Vec<u8>
{
    let pem = read_file(path);
    
    println!("Passphrase for PEM file {}",path);
    let mut input = String::new();
    
    match io::stdin().read_line(&mut input)
    {
        Err(why) => panic!("reading input: {}", why),
        Ok(_) => ()
    }

    if input.len() > 1
    {
        input.remove(input.len()-1);

        let rsa_input = Rsa::private_key_from_pem_passphrase
        (
            pem.as_bytes(),
            input.as_bytes()
        );
    
        match rsa_input
        {
            Err(why) => panic!("when obtaining private key from pem file, {}, {}", path, why),
            Ok(_) => ()
        }
    
        let rsa = rsa_input.unwrap();
    
        let mut buf = vec![0; rsa.size() as usize];
        let len = rsa.public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
        return buf
    }
    else 
    {
        panic!("passphrase is empty");
    }
}
