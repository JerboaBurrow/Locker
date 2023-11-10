use core::panic;
use std::io;

use locker::
{
    crypto::
    {
        encrypt,
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

    println!("Enter some data to encrypt:");
    let mut input = String::new();
    
    match io::stdin().read_line(&mut input)
    {
        Err(why) => panic!("reading input: {}", why),
        Ok(_) => ()
    }

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

    let rsa = build_rsa(pem.as_str(), pass.as_str());

    let result = encrypt(rsa, input.as_bytes());

    util::write_file("out", &result);
}