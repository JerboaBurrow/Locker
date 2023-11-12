/*!

    A .lkr file consists of a json array of data 
        entries. Each entry contains a hash (of the key)
        and an encrypted string (the value)

    All keys (hashes) are enforced to be unique

    [
        {
            "hash": "5B91F44FE9A4F000A26BAF9C6D072BFD6C79790B2D5CC84FF6B46EA814E1F02D",
            "value": "58B6E0170CBFB28CC25DAB7A099E1B245F8717A0C04E57CFF69A92A3D6CA1ED715C6D..."
        },
        {
            "hash": "...",
            "value": "..."
        },
        .
        .
        .
    ]

*/

use crate::
{
    crypto::{hash, encrypt, decrypt},
    util::{write_file, read_file_utf8, dump_bytes, read_bytes, warning}
};

use openssl::sha::Sha256;

use serde::{Deserialize, Serialize};

use std::
{
    collections::HashMap,
    fmt
};

use openssl::
{
    rsa::Rsa,
    pkey::Private
};

#[derive(Serialize, Deserialize)]
pub struct Entry 
{
    hash: String,
    value: String
}

#[derive(Serialize, Deserialize)]
pub struct Lkr
{
    check_hash: String,
    entries: Vec<Entry>
}

pub struct Locker {
    data: HashMap<[u8; 32], Vec<u8>>
}

#[derive(Debug, Clone)]
pub struct KeyCollisionError
{
    key: String
}

impl fmt::Display for KeyCollisionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "key {}, is already in lkr file", self.key)
    }
}

#[derive(Debug, Clone)]
pub struct KeyNonExistantError
{
    key: String
}

impl fmt::Display for KeyNonExistantError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "key {}, is not in lkr file", self.key)
    }
}

impl Locker 
{

    pub fn new() -> Locker
    {
        Locker { data: HashMap::new() }
    }

    pub fn contains(&self, key: &str) -> bool
    {
        let h = hash(key);
        self.data.contains_key(&h)
    }

    pub fn insert(&mut self, key: &str, value: &str, rsa: Rsa<Private>) -> Result<(), KeyCollisionError>
    {
        match self.contains(key)
        {
            false => 
            {
                let h = hash(key);
                self.data.insert(h, encrypt(rsa, value.as_bytes()));
                Ok(())
            },
            true => Err(KeyCollisionError {key: key.to_string()})
        }
    }

    pub fn get(&self, key: &str, rsa: Rsa<Private>) -> Result<String, KeyNonExistantError>
    {
        match self.contains(&key) 
        {
            false => Err(KeyNonExistantError {key: key.to_string()}),
            true =>
            {
                let h = hash(&key);
                let data = self.data.get(&h).unwrap();
                let result = decrypt(rsa, &data);
                match std::str::from_utf8(&result)
                {
                    Err(_e) => 
                    {
                        let s: Vec<String> = result.iter().map(|&c| c.to_string()).collect();
                        Ok(s.join("").to_string())
                    }
                    Ok(str) => Ok(str.to_string().trim_matches(char::from(0)).to_string())
                }
            }
        }
    }

    pub fn read(&mut self, path: &str)
    {
        let data = read_file_utf8(path);
        let lkr: Lkr = serde_json::from_str(&data).unwrap();
        let lkr_entries = lkr.entries;

        let mut check_hash: Sha256 = Sha256::new();

        for entry in lkr_entries
        {
            match entry.hash.len()
            {
                64 => {/*void*/},
                _ => {panic!("found entry with hash value of incorrect size (256 bytes) in {}", path)}
            };

            let h: [u8; 32] = read_bytes(entry.hash.clone()).try_into().unwrap();
            let v = read_bytes(entry.value.clone());

            self.data.insert(h, v);

            check_hash.update(entry.hash.as_bytes());
            check_hash.update(entry.value.as_bytes());
        }

        if lkr.check_hash != dump_bytes(&check_hash.finish())
        {
            warning(format!("Computed hash from {} does not match check hash in file, possible manipulation",path).as_str());
        }
    }

    pub fn write(&self, path: &str)
    {
        let mut data: Vec<Entry> = Vec::new();
        let mut check_hash: Sha256 = Sha256::new();
        for (hash, value) in &self.data 
        {
            let hash_string = dump_bytes(hash);
            let value_string = dump_bytes(value);

            data.push(Entry{hash: hash_string.clone(), value: value_string.clone()});
            check_hash.update(hash_string.as_bytes());
            check_hash.update(value_string.as_bytes());
        }

        match serde_json::to_string_pretty(&Lkr {check_hash: dump_bytes(&check_hash.finish()), entries: data})
        {
            Ok(se) => 
            {
                write_file(path, se.as_bytes())
            },
            Err(why) => {panic!("serde_json serialisation error: {}", why)}
        }
    }
}

