use std::process::exit;
use std::path::Path;

use locker::
{
    crypto::build_rsa,
    file::Locker,
    error::{CommandError, CommandResult}, 
    util::find_file_in_dir,
    command::{handle_command, is_command}
};

use openssl::
{
    rsa::Rsa,
    pkey::Private
};

use regex::Regex;

use rpassword;

const HELP_STRING: &str = r#"
Locker general usage (see also commands):

    locker [file.lkr] [entry] {data}

Locker commands:

    (print keys in file.lkr) locker [file.lkr] show_keys
 
  []'d arguments are required, -'d arguments are optional

  Specifying {data} will run locker in store mode, omitting
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

const PEM_FILE_REGEX: &str = r"[^\s-]*(.pem)$";
const LKR_FILE_REGEX: &str = r"[^\s-]*(.lkr)$";

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

    let (lkr_path,lkr_command, lkr_entry, lkr_data) = extract_arguments(args);

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

    let rsa = get_rsa(pem);

    match lkr_command
    {
        Some(command) =>
        {
            match handle_command(path.as_str(), rsa, &command)
            {
                Ok(status) => 
                {
                    match status 
                    {
                        CommandResult::OK => {exit(0)},
                        CommandResult::UNKNOWN => {}
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
        
                        match std::fs::copy(path.clone(), format!("{}.bk",path))
                        {
                            Ok(_) => {},
                            Err(why) => {panic!("Error when backing up lkr file {} to {}.bk: {}", path, path, why)}
                        }
                    }
        
                    match lkr.insert(entry.as_str(),&data,rsa)
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
        let re = Regex::new(PEM_FILE_REGEX).unwrap();
        match find_file_in_dir(re)
        {
            Ok(name) => {name},
            Err(why) => {println!("While detecting PEM: {}", why); exit(1);}
        }
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

fn extract_arguments(args: Vec<String>) -> (Option<String>, Option<String>, Option<String>, Option<String>)
{
    let mut path: Option<String> = None;
    let mut command: Option<String> = None;
    let mut key: Option<String> = None;
    let mut data: Option<String> = None;

    let mut args_to_parse = args.clone();

    let mut index = 0;

    loop 
    {
        if args_to_parse.is_empty() || index == args_to_parse.len() { break; }

        let arg = args_to_parse.get(index).unwrap().clone();
        let pattern = Regex::new(LKR_FILE_REGEX).unwrap();
        
        let mut consumed = false; 

        match pattern.captures(&arg)
        {
            Some(_match) => 
            {
                path = Some(arg.to_string());
                args_to_parse.remove(index);
                consumed = true;
            },
            None => {}
        }

        if is_command(arg.to_string())
        {
            command = Some(arg.to_string());
            args_to_parse.remove(index);
            consumed = true;
        }

        if !consumed
        {
            index += 1;
        }
    }

    if args_to_parse.len() >= 1
    {
        key = Some(args_to_parse.get(0).unwrap().to_string());
    }
    
    if args_to_parse.len() > 1
    {
        data = Some(args_to_parse.get(1).unwrap().to_string());
    }

    match path 
    {
        Some(_) => {},
        None => 
        {
            let re = Regex::new(LKR_FILE_REGEX).unwrap();
            match find_file_in_dir(re)
            {
                Ok(name) => {path = Some(name)},
                Err(why) => {}
            }
        }
    }

    (path, command, key, data)
}