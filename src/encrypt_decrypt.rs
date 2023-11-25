use core::panic;
use std::io;

use locker::
{
    crypto::
    {
        encrypt,
        decrypt,
        build_rsa
    }, 
    util
};

fn main()
{
    let args: Vec<String> = std::env::args().collect();

    let pem = if args.iter().any(|x| x == "-k")
    {
        let i = args.iter().position(|x| x == "-k").unwrap();
        if i+1 < args.len()
        {
            args[i+1].parse::<String>().unwrap()
        }
        else
        {
            "private.pem".to_string()
        }
    }
    else 
    {
        "private.pem".to_string()
    };

    let mut encrypted_file: String = String::new();

    let decrypting = if args.iter().any(|x| x == "-d")
    {
        let i = args.iter().position(|x| x == "-d").unwrap();
        if i+1 < args.len()
        {
            encrypted_file = args[i+1].parse::<String>().unwrap();
            true
        }
        else
        {
            panic!("No file given to decrypt");
        }
    }
    else 
    {
        false
    };

    println!("Passphrase for PEM file {}",pem);
    let mut pass = String::new();
    
    match io::stdin().read_line(&mut pass)
    {
        Err(why) => panic!("reading input: {}", why),
        Ok(_) => ()
    }

    if pass.len() > 1
    {
        pass.remove(pass.len()-1);
    }
    else 
    {
        panic!("passphrase is empty");
    }

    let rsa = build_rsa(pem.as_str(), pass.as_str()).unwrap();

    if decrypting
    {
        let data = util::read_file_raw(encrypted_file.as_str()).unwrap();
        let result = decrypt(rsa, &data);
        match std::str::from_utf8(&result)
        {
            Err(_e) => {println!("Not UTF8, dumping bytes\n"); for c in result { print!("{} ", c)}},
            Ok(str) => println!("Decypted data:  \n{}", str)
        }
        
    }
    else 
    {
        println!("Enter some data to encrypt:");
        let mut input = String::new();
        
        match io::stdin().read_line(&mut input)
        {
            Err(why) => panic!("reading input: {}", why),
            Ok(_) => ()
        }
    
        let result = encrypt(rsa, input.as_bytes());
    
        util::write_file("out", &result);
    }
}