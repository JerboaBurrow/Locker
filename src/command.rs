use crate::
{
    error::{CommandError, CommandResult},
    file::Locker, crypto::generate_key, arguments::extract_pass
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
    GenKey
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
        _ => {Ok(CommandResult::NOTHING_TO_DO)}
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