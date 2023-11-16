use std::process::exit;
use std::path::Path;

use locker::
{
    crypto::build_rsa,
    file::Locker,
    error::CommandResult, 
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

    locker entry {data}

    Specifying {data} will run locker in store mode, omitting
      it will run locker in retrieve mode.

    Locker will automatically find a private key (RSA) as 
      a .pem file, and a lkr file as a .lkr in the current
      directory (see options to specify paths)

    Options (see below) can be specified with - for options 
      without arguments, and -- for options with arguments

Locker commands:

    (print keys in file.lkr) locker show_keys

  Positional arguments:
  
    file.lkr must be specified, pointing to the locker file
    entry    must be specified, the entry to store or retrieve
    data     optional, if specified locker will attempt to 
               store data with the key given by entry
  
  Options:
  
    --k pem   path to (encrypted) RSA private key in pem 
               format

    --p pass  password for the pem file

    -o        overwrite a key

    --f lkr   path to .lkr file

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
    let mut overwrite = false;

    if args.iter().any(|x| x == "-h")
    {
        help();
    }

    if args.iter().any(|arg| arg == "-o")
    {
        let index = args.iter().position(|arg| arg == "-o").unwrap();
        args.remove(index);
        overwrite = true;
    }

    let pem = extract_pem(&mut args);

    let pass: Option<String> = extract_pass(&mut args);

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
        
    let rsa = build_rsa(pem.as_str(), &password.as_str());

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

fn help()
{
    println!("{}", HELP_STRING);
    exit(0);
}

fn extract_pass(args: &mut Vec<String>) -> Option<String>
{
    if args.iter().any(|arg| arg == "-p")
    {
        let i = args.iter().position(|x| x == "-p").unwrap();
        if i+1 < args.len()
        {
            let s = args[i+1].parse::<String>().unwrap();
            args.remove(i);
            args.remove(i);
            Some(s)
        }
        else 
        {
            None    
        }
    }
    else
    {
        None
    }
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
            return s
        }
    }

    let re = Regex::new(PEM_FILE_REGEX).unwrap();
    match find_file_in_dir(re)
    {
        Ok(name) => {name},
        Err(why) => {println!("While detecting PEM: {}", why); exit(1);}
    }
}

fn extract_lkr(args: &mut Vec<String>) -> String
{
    if args.iter().any(|x| x == "-f")
    {
        let i = args.iter().position(|x| x == "-f").unwrap();
        if i+1 < args.len()
        {
            let s = args[i+1].parse::<String>().unwrap();
            args.remove(i);
            args.remove(i);
            return s
        }
    }
    let re = Regex::new(LKR_FILE_REGEX).unwrap();
    match find_file_in_dir(re)
    {
        Ok(name) => {return name},
        Err(why) => {println!("While detecting .lkr: {}", why); exit(1);}
    }
}

fn extract_arguments(args: Vec<String>) -> (Option<String>, Option<String>, Option<String>, Option<String>)
{
    let mut path: Option<String> = None;
    let mut command: Option<String> = None;
    let mut key: Option<String> = None;
    let mut data: Option<String> = None;

    let mut args_to_parse = args.clone();

    let mut index = 0;

    path = Some(extract_lkr(&mut args_to_parse));

    loop 
    {
        if args_to_parse.is_empty() || index == args_to_parse.len() { break; }

        let arg = args_to_parse.get(index).unwrap().clone();

        if is_command(arg.to_string())
        {
            command = Some(arg.to_string());
            args_to_parse.remove(index);
            index += 1
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
                Err(_why) => {}
            }
        }
    }

    (path, command, key, data)
}