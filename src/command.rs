use crate::
{
    error::{CommandError, CommandResult},
    file::{Locker, EntryPlainText}, crypto::{generate_key, build_rsa}, arguments::extract_pass, util::{write_file, read_file_utf8}
};

use std::path::Path;

use openssl::
{
    rsa::Rsa,
    pkey::Private
};

#[derive(Debug, Clone)]
pub enum CommandCode
{
    ShowKeys,
    GenKey,
    ReKey,
    Export,
    Import
}

#[derive(Debug, Clone)]
pub struct Command 
{
    code: CommandCode,
    argument: Option<String>,
    data: Option<String>
}

pub fn extract_command(args: &mut Vec<String>) -> Result<Option<Command>, CommandError>
{

    if args.iter().any(|x| x == "-show_keys")
    {
        let i = args.iter().position(|x| x == "-show_keys").unwrap();
        args.remove(i);
        return Ok(Some(Command { code: CommandCode::ShowKeys, argument: None, data: None}));
    }

    if args.iter().any(|x| x == "--export")
    {
        let i = args.iter().position(|x| x == "--export").unwrap();

        if i+1 < args.len()
        {
            let s = args[i+1].parse::<String>().unwrap();
            if s.find("-").is_none()
            {
                args.remove(i);   
                args.remove(i);
                return Ok(Some(Command { code: CommandCode::Export, argument: Some(s), data: None }));
            }
            else 
            {
                args.remove(i);
                return Ok(Some(Command { code: CommandCode::Export, argument: None, data: None}));
            }
        }
        else
        {
            args.remove(i);
            return Ok(Some(Command { code: CommandCode::Export, argument: None, data: None }));
        }
    }

    if args.iter().any(|x| x == "--import")
    {
        let i = args.iter().position(|x| x == "--import").unwrap();

        if i+1 < args.len()
        {
            let s = args[i+1].parse::<String>().unwrap();
            if s.find("-").is_none()
            {
                args.remove(i);   
                args.remove(i);
                return Ok(Some(Command { code: CommandCode::Import, argument: Some(s), data: None }));
            }
            else 
            {
                args.remove(i);
                return Ok(Some(Command { code: CommandCode::Import, argument: None, data: None}));
            }
        }
        else
        {
            args.remove(i);
            return Ok(Some(Command { code: CommandCode::Import, argument: None, data: None }));
        }
    }

    if args.iter().any(|x| x == "--gen_key")
    {
        let i = args.iter().position(|x| x == "--gen_key").unwrap();

        if i+1 < args.len()
        {
            let s = args[i+1].parse::<String>().unwrap();
            if s.find("-").is_none()
            {
                args.remove(i);   
                args.remove(i);
                return Ok(Some(Command { code: CommandCode::GenKey, argument: Some(s), data: extract_pass(args)}));
            }
            else 
            {
                args.remove(i);
                return Ok(Some(Command { code: CommandCode::GenKey, argument: None, data: extract_pass(args)}));
            }
        }
        else
        {
            args.remove(i);
            return Ok(Some(Command { code: CommandCode::GenKey, argument: None, data: extract_pass(args)}));
        }
    }

    if args.iter().any(|x| x == "--re_key")
    {
        let i = args.iter().position(|x| x == "--re_key").unwrap();

        if i+2 < args.len()
        {
            let s = args[i+1].parse::<String>().unwrap();
            let p = args[i+2].parse::<String>().unwrap();
            
            if s.find("-").is_none() && p.find("-").is_none()
            {
                args.remove(i);   
                args.remove(i);
                args.remove(i);
                return Ok(Some(Command { code: CommandCode::ReKey, argument: Some(s), data: Some(p) }));
            }
            else if s.find("-").is_none()
            {
                args.remove(i);   
                args.remove(i);
                return Ok(Some(Command { code: CommandCode::ReKey, argument: Some(s), data: None }));
            }
            else 
            {
                args.remove(i);
                return Ok(Some(Command { code: CommandCode::ReKey, argument: None, data: None }));
            }
            
        }
        if i+1 < args.len()
        {
            let s = args[i+1].parse::<String>().unwrap();
            if s.find("-").is_none()
            {
                args.remove(i);   
                args.remove(i);
                return Ok(Some(Command { code: CommandCode::ReKey, argument: Some(s), data: None }));
            }
            else 
            {
                args.remove(i);
                return Ok(Some(Command { code: CommandCode::ReKey, argument: None, data: None }));
            }
        }
        else
        {
            args.remove(i);
            return Ok(Some(Command { code: CommandCode::ReKey, argument: None, data: None }));
        }
    }

    Ok(None)
}

pub fn handle_free_command(command: Command) -> Result<CommandResult, CommandError>
{
    match command.code 
    {
        CommandCode::GenKey => 
        {
            match command.data
            {
                Some(data) => { gen_key(command.argument, Some(data.clone())) },
                None => { gen_key(command.argument, None) }
            }
        },
        _ => {Ok(CommandResult::NothingToDo)}
    }
}

pub fn handle_command(lkr_path: &str, rsa: Rsa<Private>, command: Command) -> Result<CommandResult, CommandError>
{
    match command.code
    {
        CommandCode::ShowKeys => 
        {
            show_keys(lkr_path, rsa)
        },
        CommandCode::ReKey =>
        {
            re_key(lkr_path, rsa, command.argument, command.data)
        },
        CommandCode::Export =>
        {
            export(lkr_path, rsa, command.argument)
        },
        CommandCode::Import =>
        {
            import(lkr_path, rsa, command.argument)
        }
        _ => {Ok(CommandResult::NothingToDo)}
    }
}

fn export(lkr_path: &str, rsa: Rsa<Private>, path: Option<String>) -> Result<CommandResult, CommandError>
{
    if !Path::new(lkr_path).exists()
    {
        return Err(CommandError { why: format!("show_keys, lkr file {} does not exist", lkr_path) });
    }

    let mut lkr = Locker::new();

    match lkr.read(&lkr_path)
    {
        Ok(_) => {},
        Err(why) => 
        {
            return Err(CommandError{why: format!("{}", why)})
        }
    }

    let mut plaintext: Vec<EntryPlainText> = Vec::new();

    for key in lkr.get_keys(rsa.clone())
    {
        plaintext.push(EntryPlainText{ key: key.clone(), value: lkr.get(&key, rsa.clone()).unwrap()});
    }

    let export_path = match path 
    {
        Some(p) => p,
        None => { "exported".to_string() }
    };

    match serde_json::to_string_pretty(&plaintext)
    {
        Ok(se) => 
        {
            write_file(&export_path, se.as_bytes())
        },
        Err(why) => 
        {
            return Err(CommandError { why: format!("serde_json serialisation error: {}", why)})
        }
    }

    Ok(CommandResult::OK)
    
}

fn import(lkr_path: &str, rsa: Rsa<Private>, path: Option<String>) -> Result<CommandResult, CommandError>
{
    let in_file = match path 
    {
        Some(f) => f,
        None => 
        {
            return Err(CommandError { why: format!("no import path given as argument to --import") });
        }
    };

    let data_string = match read_file_utf8(&in_file)
    {
        Ok(d) => d, 
        Err(e) => 
        {
            return Err(CommandError { why: format!("Could not read import file {}: {}", in_file, e) });
        }
    };

    let data: Vec<EntryPlainText> = match serde_json::from_str(&data_string)
    {
        Ok(d) => d,
        Err(e) => {return Err(CommandError { why: format!("Could not parse import file {}: {}", in_file, e) });}
    };


    let mut lkr = Locker::new();

    match Path::new(lkr_path).exists()
    {
        true => {lkr.read(lkr_path).unwrap();},
        false => ()
    }

    for entry in data 
    {
        lkr.insert(&entry.key, &entry.value, rsa.clone(), false).unwrap();
    }

    match lkr.write(lkr_path)
    {
        Ok(_) => Ok(CommandResult::OK),
        Err(e) => {return Err(CommandError { why:format!("{}", e) });}
    }

}

fn re_key(lkr_path: &str, old_rsa: Rsa<Private>, path: Option<String>, pass: Option<String>) -> Result<CommandResult, CommandError>
{

    match gen_key(path.clone(), pass.clone())
    {
        Ok(_r) => (),
        Err(e) => return Err(e)
    }

    let mut old_lkr = Locker::new();
    let mut lkr = Locker::new();

    if !Path::new(lkr_path).exists()
    {
        return Err(CommandError { why: format!("Locker file {}, does not exit", lkr_path) });
    }
    
    match old_lkr.read(lkr_path)
    {
        Ok(_) => (),
        Err(why) => 
        {
            return Err(CommandError { why: format!("{}", why) });
        }
    }

    let pem = match path
    {
        Some(p) => p,
        None => "locker.pem".to_string()
    };

    let password = match pass 
    {
        Some(s) => s,
        None => 
        {
            rpassword::prompt_password
            (
                format!("Re enter passphrase for new key: ")
            ).unwrap()
        }
    };

    let rsa = match build_rsa(pem.as_str(), password.as_str())
    {
        Ok(v) => v,
        Err(e) => 
        {
            println!("{}", e.why);
            std::process::exit(1);
        }
    };


    for key in old_lkr.get_keys(old_rsa.clone())
    {
        let value = old_lkr.get(&key, old_rsa.clone()).unwrap();
        lkr.insert(&key, &value, rsa.clone(), true).unwrap();
    }

    match lkr.write(lkr_path)
    {
        Ok(_) => Ok(CommandResult::OK),
        Err(why) => { Err(CommandError { why: format!("{}", why) }) }
    }
}

fn gen_key(path: Option<String>, pass: Option<String>) -> Result<CommandResult, CommandError>
{
    let result = match path
    {
        Some(p) => generate_key(&p, pass),
        None => generate_key("locker.pem", pass)
    };

    match result
    {
        Ok(_) => Ok(CommandResult::OK),
        Err(e) => Err(CommandError { why: format!("While generating key: {}", e) })
    }
}

fn show_keys(lkr_path: &str, rsa: Rsa<Private>) -> Result<CommandResult, CommandError>
{

    if !Path::new(lkr_path).exists()
    {
        return Err(CommandError { why: format!("show_keys, lkr file {} does not exist", lkr_path) });
    }

    let mut lkr = Locker::new();

    match lkr.read(&lkr_path)
    {
        Ok(_) => {},
        Err(why) => 
        {
            return Err(CommandError{why: format!("{}", why)})
        }
    }
    
    let keys = lkr.get_keys(rsa);

    for key in keys 
    {
        println!("{}", key);
    }

    Ok(CommandResult::OK)
}