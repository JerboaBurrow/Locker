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
    crypto::{hash, encrypt, decrypt, decrypt_string},
    util::{write_file, read_file_utf8, dump_bytes, read_bytes, warning}, 
    program_version,
    compatible
};

use semver::Version;

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
pub struct Lkr0_1_0
{
    version: String,
    check_hash: String,
    entries: Vec<Entry>
}

#[derive(Serialize, Deserialize)]
pub struct Lkr
{
    version: String,
    check_hash: String,
    entries: Vec<Entry>,
    keys: Vec<String>
}

pub struct Locker {
    data: HashMap<[u8; 32], Vec<u8>>,
    keys: Vec<Vec<u8>>
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
        Locker { data: HashMap::new(), keys: Vec::new() }
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
                self.data.insert(h, encrypt(rsa.clone(), value.as_bytes()));
                self.keys.push(encrypt(rsa, key.as_bytes()));
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
                Ok(decrypt_string(data.to_vec(), rsa))
            }
        }
    }

    pub fn get_keys(&self, rsa: Rsa<Private>) -> Vec<String>
    {
        let mut keys: Vec<String> = Vec::new();
        for key in &self.keys
        {   
            keys.push(decrypt_string(key.to_vec(), rsa.clone()));
        }
        keys
    }

    pub fn read(&mut self, path: &str)
    {
        let data = read_file_utf8(path);

        match data.find("\"version\": [")
        {
            Some(_) => {panic!("Incompatible lkr file {}, version 0.1.0, loaded in newer release, {}", path, program_version())},
            None => {}
        }

        let lkr: Lkr = match serde_json::from_str(&data)
        {
            Ok(data) => {data},
            Err(why) => {panic!("Error while loading lkr file {}: {}", path, why)}
        };

        let lkr_entries = lkr.entries;
        let lkr_keys = lkr.keys;

        let file_version = Version::parse(lkr.version.as_str()).unwrap();

        if file_version != program_version()
        {
            let compat_info = match compatible(program_version(), file_version.clone())
            {
                true => "[compatible] ",
                false => "[incompatible] "
            };

            let msg = format!
            (
                "{}version mismatch: program {} lkr file: {}",
                compat_info,
                program_version(),
                file_version
            );

            warning(&msg);
        }

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

        for key in lkr_keys
        {
            let k = read_bytes(key);
            self.keys.push(k.clone());
            check_hash.update(&k);
        }

        if lkr.check_hash != dump_bytes(&check_hash.finish())
        {
            warning(format!("Computed hash from {} does not match check hash in file, possible manipulation",path).as_str());
        }
    }

    pub fn write(&self, path: &str)
    {
        let mut data: Vec<Entry> = Vec::new();
        let mut keys: Vec<String> = Vec::new();
        let mut check_hash: Sha256 = Sha256::new();

        for (hash, value) in &self.data 
        {
            let hash_string = dump_bytes(hash);
            let value_string = dump_bytes(value);

            data.push(Entry{hash: hash_string.clone(), value: value_string.clone()});
            check_hash.update(hash_string.as_bytes());
            check_hash.update(value_string.as_bytes());
        }

        for key in &self.keys
        {
            let key_string = dump_bytes(&key);

            keys.push(key_string.clone());
            check_hash.update(key_string.as_bytes());
        }

        let v = program_version();

        let lkr = Lkr
        {
            version: v.to_string(), 
            check_hash: dump_bytes(&check_hash.finish()), 
            entries: data,
            keys
        };

        match serde_json::to_string_pretty(&lkr)
        {
            Ok(se) => 
            {
                write_file(path, se.as_bytes())
            },
            Err(why) => {panic!("serde_json serialisation error: {}", why)}
        }
    }
}

