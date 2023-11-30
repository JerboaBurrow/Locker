use crate::
{
    error::{CommandError, CommandResult},
    file::Locker
};

use std::path::Path;

use openssl::
{
    rsa::Rsa,
    pkey::Private
};

pub enum CommandCode
{
    ShowKeys
}

pub struct Command 
{
    code: CommandCode,
    argument: Option<String>
}

pub fn extract_command(args: &mut Vec<String>) -> Result<Option<Command>, CommandError>
{
    if args.iter().any(|x| x == "-show_keys")
    {
        let i = args.iter().position(|x| x == "--show_keys").unwrap();
        args.remove(i);
        return Ok(Some(Command { code: CommandCode::ShowKeys, argument: None}));
    }

    Ok(None)
}

pub fn handle_command(lkr_path: &str, rsa: Rsa<Private>, command: Command) -> Result<CommandResult, CommandError>
{
    match command.code
    {
        CommandCode::ShowKeys => 
        {
            show_keys(lkr_path, rsa)
        },
        _ => {Ok(CommandResult::UNKNOWN)}
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