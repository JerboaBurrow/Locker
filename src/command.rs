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

const COMMAND_LIST: &[&str] = &["show_keys"];

pub fn handle_command(lkr_path: &str, rsa: Rsa<Private>, command: &str) -> Result<CommandResult, CommandError>
{
    match command
    {
        "show_keys" => 
        {
            show_keys(lkr_path, rsa)
        },
        _ => {Ok(CommandResult::UNKNOWN)}
    }
}

pub fn is_command(command: String) -> bool
{
    if COMMAND_LIST.contains(&command.as_str())
    {
        true
    }
    else 
    {
        false    
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