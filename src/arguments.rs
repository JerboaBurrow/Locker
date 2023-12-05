use regex::Regex;

use crate::
{
    util::{find_file_in_dir, warning}, 
    error::{NoSuchFileError, ArgumentError}
};

pub fn extract_pass(args: &mut Vec<String>) -> Option<String>
{
    if args.iter().any(|arg| arg == "--p")
    {
        let i = args.iter().position(|x| x == "--p").unwrap();
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

const PEM_FILE_REGEX: &str = r"[^\s-]*(.pem)$";
const LKR_FILE_REGEX: &str = r"[^\s-]*(.lkr)$";

pub fn extract_pem(args: &mut Vec<String>) -> Result<String, NoSuchFileError>
{
    if args.iter().any(|x| x == "--k")
    {
        let i = args.iter().position(|x| x == "--k").unwrap();
        if i+1 < args.len()
        {
            let s = args[i+1].parse::<String>().unwrap();
            args.remove(i);
            args.remove(i);
            return Ok(s)
        }
    }

    let re = Regex::new(PEM_FILE_REGEX).unwrap();
    match find_file_in_dir(re)
    {
        Ok(name) => Ok(name),
        Err(why) => 
        {
            Err(why)
        }
    }
}

pub fn extract_lkr(args: &mut Vec<String>) -> Option<String>
{
    if args.iter().any(|x| x == "--f")
    {
        let i = args.iter().position(|x| x == "--f").unwrap();
        if i+1 < args.len()
        {
            let s = args[i+1].parse::<String>().unwrap();
            args.remove(i);
            args.remove(i);
            return Some(s)
        }
    }
    let re = Regex::new(LKR_FILE_REGEX).unwrap();
    match find_file_in_dir(re)
    {
        Ok(name) => Some(name),
        Err(_why) => None
    }
}

pub fn extract_arguments(args: Vec<String>) -> Result<(Option<String>, Option<String>, Option<String>), ArgumentError>
{
    let mut key: Option<String> = None;
    let mut data: Option<String> = None;

    let mut args_to_parse = args.clone();

    let mut index = 0;

    let path: Option<String> = extract_lkr(&mut args_to_parse);

    loop 
    {
        if args_to_parse.is_empty() || index == args_to_parse.len() { break; }

        let arg = args_to_parse.get(index).unwrap().clone();

        if arg.starts_with("-") || arg.starts_with("--")
        {
            warning(format!("Unhandled command: {}", arg).as_str());
            args_to_parse.remove(index);
        }
        else 
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

    Ok((path, key, data))
}