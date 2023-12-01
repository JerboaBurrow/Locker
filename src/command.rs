use crate::
{
    error::{CommandError, CommandResult},
    file::Locker, crypto::{generate_key, build_rsa}, arguments::extract_pass
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
    Export
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
        _ => {Ok(CommandResult::NOTHING_TO_DO)}
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
        _ => {Ok(CommandResult::NOTHING_TO_DO)}
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

    match std::fs::copy(lkr_path, format!("{}.bk",lkr_path))
    {
        Ok(_) => {},
        Err(why) => {return Err(CommandError{ why: format!("Error when backing up lkr file {} to {}.bk: {}", lkr_path, lkr_path, why)})}
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