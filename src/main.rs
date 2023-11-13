use std::process::exit;
use std::path::Path;

use locker::
{
    crypto::build_rsa,
    file::Locker
};

use openssl::
{
    rsa::Rsa,
    pkey::Private
};

use rpassword;

const HELP_STRING: &str = r#"
Locker usage:

    locker [file.lkr] [entry] {data} {-k private_key.pem}
    
  []'d arguments are required, {}'d arguments are optional.

  Specifying {data} will run locker in store mode, ommiting
    it will run locker in retrieve mode.

  Positional arguments:
  
    file.lkr must be specified, pointing to the locker file
    entry    must be specified, the entry to store or retrieve
    data     optional, if specified locker will attempt to 
               store data with the key given by entry
  
  Options:
  
    -k pem   path to (encrypted) RSA private key in pem 
               format
Notes:

  In storage mode locker will backup the locker file's prior
    state. E.g. file.lkr will be backed-up as file.lkr.bk.

  When in storage mode a key collision will prompt for
    whether to quit, or overwrite."#;

fn main()
{
    let mut args: Vec<String> = std::env::args().collect();

    if args.iter().any(|x| x == "-h")
    {
        help();
    }

    let pem = extract_pem(&mut args);

    let mut lkr: Locker = Locker::new();

    // strip program argument
    args.remove(0);

    let (lkr_path, lkr_entry, lkr_data) = if args.len() == 2
    {
        (args.get(0).unwrap(), args.get(1).unwrap(), None)
    }
    else if args.len() == 3
    {
        (args.get(0).unwrap(), args.get(1).unwrap(), Some(args.get(2).unwrap()))
    }
    else 
    {
        println!("No lkr file given as first argument, or entry as second, run locker file.lkr [value] {{data}} {{-k priv.pem}}");
        help();
        // compile requires this here
        exit(0);
    };

    let rsa = get_rsa(pem);

    match lkr_data 
    {
        None => 
        {
            if !Path::new(lkr_path).exists()
            {
                println!("Locker file {}, does not exit", lkr_path);
                exit(0);
            }

            lkr.read(&lkr_path);

            match lkr.get(&lkr_entry,rsa)
            {
                Ok(value) => {println!("retrived: {}", value);},
                Err(why) => {println!("Key does not exist {}", why); exit(0)}
            }
        },
        Some(data) => 
        {

            if Path::new(lkr_path).exists()
            {
                match std::fs::copy(lkr_path, format!("{}.bk",lkr_path))
                {
                    Ok(_) => {},
                    Err(why) => {panic!("Error when backing up lkr file {} to {}.bk: {}", lkr_path, lkr_path, why)}
                }
            }

            match lkr.insert(&lkr_entry,data,rsa)
            {
                Ok(_) => {},
                Err(why) => {println!("Key already exists {}", why); exit(0)}
            }

            lkr.write(&lkr_path);
        }
    }
    
}

fn help()
{
    println!("{}", HELP_STRING);
    exit(0);
}

fn extract_pem(args: &mut Vec<String>) -> String
{
    if args.iter().any(|x| x == "-k")
    {
        let i = args.iter().position(|x| x == "-k").unwrap();
        if i+1 < args.len()
        {
            let s = args[i+1].parse::<String>().unwrap();
            args.remove(i);
            args.remove(i);
            s
        }
        else
        {
            args.remove(i);
            "private.pem".to_string()
        }
    }
    else 
    {
        "private.pem".to_string()
    }
}

fn get_rsa(pem: String) -> Rsa<Private>
{
    let pass = rpassword::prompt_password
    (
        format!("Passphrase for PEM file {}: ",pem)
    ).unwrap();

    let rsa = build_rsa(pem.as_str(), pass.as_str());

    rsa
}