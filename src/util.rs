use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

pub fn read_file_utf8(path: &str) -> String
{
    let path = Path::new(path);
    let display = path.display();

    // Open the path in read-only mode, returns `io::Result<File>`
    let mut file = match File::open(path) {
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => panic!("couldn't read {}: {}", display, why),
        Ok(_) => s
    }

}

pub fn write_file(path: &str, data: &[u8])
{
    let mut file = File::create(path).unwrap();
    file.write_all(data).unwrap();
}

pub fn read_file_raw(path: &str) -> Vec<u8>
{
    match std::fs::read(path)
    {
        Err(why) => panic!("Couldn't read {}: {}", path, why),
        Ok(data) => data
    }
}