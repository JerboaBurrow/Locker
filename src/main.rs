use std::process::exit;
use std::path::Path;

use locker::
{
    crypto::build_rsa,
    file::Locker,
    error::CommandResult, 
    command::{extract_command, handle_command, handle_free_command},
    arguments::{extract_arguments, extract_pass, extract_pem},
    program_version
};

use rpassword;

const HELP_STRING: &str = r#"
Locker is a lightweight encrypted key-value data store 
  written in Rust, using OpenSSL (via rust-openssl) 
  for cryptography.

The source code is licensed under the GPL V3 
  https://github.com/JerboaBurrow/Locker

Caution this software has no independent security audit. 
 However, cryptography is supplied by OpenSSL via rust-openssl, 
 use at your own risk.

Locker general usage:

    locker entry [data]

    []'d values are optional

    Specifying [data] will run locker in store mode, omitting
      it will run locker in retrieve mode.

    Locker will automatically find a private key (RSA) as 
      a .pem file, and a lkr file as a .lkr in the current
      directory (see options to specify paths)

    Options (see below) can be specified with - for options 
      without arguments, and -- for options with arguments

  Positional arguments:
  
    entry    can be specified, the entry to store or retrieve
    data     optional, if specified locker will attempt to 
               store data with the key given by entry
  
  Options:
  
    --k pem          path to (encrypted) RSA private key in pem 
                       format

    --p pass         password for the pem file

    -o               overwrite a key

    -d               delete a key

    --f lkr          path to .lkr file

    -show_keys       print all keys in .lkr file

    --gen_key [pem]  generates an AES256 encrypted RSA
                       private key (with passphrase).
                       Writes to [pem] if specified or
                       'locker.pem' if not

    --re_key [pem]   generates a new AES256 encrypted RSA
                       private key, and transfers data from 
                       locker file to a new locker file 
                       encrypted with the new key.
                       Writes the key to [pem] if specified 
                       or 'locker.pem' if not
    
    --import file    import data in JSON format
                       from file

    --export [file]  export data in JSON format.
                       if [file] is specified Locker
                       will output for [file], otherwise
                       data will be export to 'exported'
                       in the current directory


Notes:

  Locker will always create a backup copy of the given .lkr file
    as a .lkr.bk, when data is written in any context.

  By default if a key already exists Locker will not overwrite 
    its value. If you wish to re-write a key's value specify -o to 
    overwrite"#;

fn main()
{
    let mut args: Vec<String> = std::env::args().collect();
    let mut overwrite = false;
    let mut delete = false;

    if args.iter().any(|x| x == "-h")
    {
        println!("Version: {}", program_version());
        help();
    }

    if args.iter().any(|x| x == "-v")
    {
        println!("Version: {}", program_version());
        std::process::exit(0);
    }

    if args.iter().any(|arg| arg == "-o")
    {
        let index = args.iter().position(|arg| arg == "-o").unwrap();
        args.remove(index);
        overwrite = true;
    }

    if args.iter().any(|arg| arg == "-d")
    {
        let index = args.iter().position(|arg| arg == "-d").unwrap();
        args.remove(index);
        delete = true;
    }

    let mut lkr: Locker = Locker::new();

    // strip program argument
    args.remove(0);

    let lkr_command = match extract_command(&mut args)
    {
        Ok(cmd) => cmd,
        Err(e) => 
        {
            println!("Error extracting commands: {}", e);
            std::process::exit(1);
        }
    };

    match lkr_command.clone()
    {
        Some(command) => 
        {
            match handle_free_command(command)
            {
                Ok(status) => 
                {
                    match status 
                    {
                        CommandResult::OK => {exit(0)},
                        CommandResult::NothingToDo => {}
                    }
                }
                Err(why) => 
                {
                    println!("{}", why); exit(1);
                }
            }
        },
        None => {}
    }

    let pem = match extract_pem(&mut args)
    {
        Ok(p) => p,
        Err(e) => 
        {
            println!("Could not find PEM: {}", e);
            std::process::exit(1);
        }
    };

    let pass: Option<String> = extract_pass(&mut args);

    let (lkr_path, lkr_entry, lkr_data) = match extract_arguments(args)
    {
        Ok(args) => args,
        Err(e) =>
        {
            println!("Command line arguments malformed: {}", e);
            std::process::exit(1);
        }
    };

    if lkr_command.is_none() && lkr_entry.is_none()
    {
        println!("No command or entry key provided, nothing to do");
        exit(1);
    }

    if lkr_path.is_none()
    {
        println!("Could not find lkr file (in this directory, or in program arguments)");
        exit(1);
    }

    let path = lkr_path.unwrap();

    let password = match pass 
    {
        Some(s) => s,
        None => 
        {
            rpassword::prompt_password
            (
                format!("Passphrase for PEM file {}: ",pem)
            ).unwrap()
        }
    };
        
    let rsa = match build_rsa(pem.as_str(), &password.as_str())
    {
        Ok(v) => v,
        Err(e) => 
        {
            println!("{}", e.why);
            std::process::exit(1);
        }
    };

    match lkr_command
    {
        Some(command) =>
        {
            match handle_command(path.as_str(), rsa, command)
            {
                Ok(status) => 
                {
                    match status 
                    {
                        CommandResult::OK => {exit(0)},
                        CommandResult::NothingToDo => {}
                    }
                }
                Err(why) => 
                {
                    println!("{}", why); exit(1);
                }
            }
        },
        None => 
        {
            
            let entry = match lkr_entry
            {
                Some(e) => {e}
                None =>
                {
                    println!("No entry key specified, nothing to do");
                    exit(1);
                }
            };

            if delete
            {
                if !Path::new(path.as_str()).exists()
                {
                    println!("Locker file {}, does not exit", path);
                    exit(0);
                }
    
                match lkr.read(path.as_str())
                {
                    Ok(_) => {},
                    Err(why) => 
                    {
                        println!("{}", why);
                        exit(1);
                    }
                }

                match lkr.delete(&entry, rsa)
                {
                    Ok(_) => (),
                    Err(e) => 
                    {
                        println!("Not key to delete: {}", e);
                        std::process::exit(1);
                    }
                }

                match lkr.write(path.as_str())
                {
                    Ok(_) => {},
                    Err(why) => 
                    {
                        println!("{}", why);
                        exit(1);
                    }
                }
            }
            else
            {
                match lkr_data 
                {
                    None => 
                    {
                        if !Path::new(path.as_str()).exists()
                        {
                            println!("Locker file {}, does not exit", path);
                            exit(0);
                        }
            
                        match lkr.read(path.as_str())
                        {
                            Ok(_) => {},
                            Err(why) => 
                            {
                                println!("{}", why);
                                exit(1);
                            }
                        }
            
                        match lkr.get(entry.as_str(),rsa)
                        {
                            Ok(value) => {println!("retrieved: {}", value);},
                            Err(why) => {println!("Key does not exist: {}", why); exit(0)}
                        }
                    },
                    Some(data) => 
                    {
            
                        if Path::new(path.as_str()).exists()
                        {
                            match lkr.read(path.as_str())
                            {
                                Ok(_) => {},
                                Err(why) => 
                                {
                                    println!("{}", why);
                                    exit(1);
                                }
                            }
                        }
            
                        match lkr.insert(entry.as_str(),&data,rsa, overwrite)
                        {
                            Ok(_) => {},
                            Err(why) => {println!("Key already exists {}", why); exit(0)}
                        }
                        
                        match lkr.write(path.as_str())
                        {
                            Ok(_) => {},
                            Err(why) => 
                            {
                                println!("{}", why);
                                exit(1);
                            }
                        }
                    }
                }
            }
        }
    }
    
}

fn help()
{
    println!("{}", HELP_STRING);
    exit(0);
}