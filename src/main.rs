use core::panic;
use std::io;

use locker::{crypto, util};

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

    let result = crypto::encrypt(pem.as_str(), input);

    util::write_file("out", &result);
}