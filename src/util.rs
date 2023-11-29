use std::path::Path;
use std::fs::File;
use std::fmt::Write as fmtWrite;
use std::io::Write as ioWrite;
use std::io::Read;
use libflate::deflate::{Encoder, Decoder};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use base64::{Engine as _, engine::general_purpose};

use regex::Regex;

use crate::error::{NoSuchFileError, ReadFileError, CompressionError};

pub fn read_file_utf8(path: &str) -> Result<String, ReadFileError>
{
    let os_path = Path::new(path);
    let display = os_path.display();

    // Open the path in read-only mode, returns `io::Result<File>`
    let mut file = match File::open(path) {
        Err(why) => 
        {
            return Err
            (
                ReadFileError 
                {
                    why: format!("couldn't open: {}", why), 
                    file: display.to_string()
                }
            )
        },
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => 
        {
            Err(
                ReadFileError
                {
                    why: format!("couldn't read: {}", why),
                    file: display.to_string()
                }
            )
        },
        Ok(_) => Ok(s)
    }

}

pub fn write_file(path: &str, data: &[u8])
{
    let mut file = File::create(path).unwrap();
    file.write_all(data).unwrap();
}

pub fn read_file_raw(path: &str) -> Result<Vec<u8>, ReadFileError>
{
    match std::fs::read(path)
    {
        Err(why) => 
        {
            Err
            (
                ReadFileError
                {
                    why: format!("Couldn't read: {}", why),
                    file: path.to_string()
                }
            )
        },
        Ok(data) => Ok(data)
    }
}

pub fn dump_bytes(v: &[u8]) -> String 
{
    let mut byte_string = String::new();
    for &byte in v
    {
        write!(&mut byte_string, "{:0>2X}", byte).expect("byte dump error");
    };
    byte_string
}

pub fn read_bytes(v: String) -> Vec<u8>
{
    (0..v.len()).step_by(2)
    .map
    (
        |index| u8::from_str_radix(&v[index..index+2], 16).unwrap()
    )
    .collect()
}

pub fn warning(msg: &str)
{
    println!("[WARNING] {}", msg);
}

pub fn find_file_in_dir(pattern: Regex) -> Result<String, NoSuchFileError>
{
    match std::fs::read_dir(".")
    {
        Ok(files) => 
        {
            let mut found_file = String::new();
            for file in files 
            {
                let file_os_string = file.unwrap().file_name();
                let file_string = match file_os_string.to_str()
                {
                    Some(name) => {name},
                    None => {continue;}
                };

                match pattern.captures(file_string)
                {
                    Some(_caps) => {found_file = file_string.to_string(); break},
                    None => {continue;}
                }
            }

            match found_file.is_empty()
            {
                true => {Err(NoSuchFileError{why: format!("No match for pattern: {}", pattern)})},
                false => {Ok(found_file)}
            }
        },
        Err(why) => 
        {
            Err(NoSuchFileError{why: format!("Error while reading directory: {}", why)})
        }
    }
}

pub fn compress(bytes: &[u8]) -> Result<Vec<u8>, CompressionError>
{
    let mut encoder = Encoder::new(Vec::new());
    
    match encoder.write_all(&bytes)
    {
        Ok(_) => (),
        Err(e) => 
        {
            return Err(CompressionError { why: format!("Error writing to compressor: {}", e) })
        }
    };

    match encoder.finish().into_result()
    {
        Ok(data) => Ok(data), 
        Err(e) => 
        {
            Err(CompressionError { why: format!("Error finalising compressor: {}", e) })
        }
    }
}

pub fn decompress(bytes: Vec<u8>) -> Result<String, CompressionError>
{
    let mut decoder = Decoder::new(&bytes[..]);
    let mut decoded_data = Vec::new();

    match decoder.read_to_end(&mut decoded_data)
    {
        Ok(_) => (),
        Err(e) => 
        {
            return Err(CompressionError { why: format!("Error decoding data: {}", e) })
        }
    }
    
    match std::str::from_utf8(&decoded_data)
    {
        Ok(s) => Ok(s.to_string()),
        Err(e) => 
        {
            Err(CompressionError { why: format!("Decoded data is not utf8: {}", e) })
        }
    }
}

// https://gist.github.com/silmeth/62a92e155d72bb9c5f19c8cdf4c8993e, updated

pub fn as_base64<T: AsRef<[u8]>, S: Serializer>(val: &T, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&general_purpose::STANDARD_NO_PAD.encode(val))
}

pub fn from_base64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    use serde::de;

    <&str>::deserialize(deserializer).and_then(|s| {
        general_purpose::STANDARD_NO_PAD.decode(s)
            .map_err(|e| de::Error::custom(format!("invalid base64 string: {}, {}", s, e)))
    })
}