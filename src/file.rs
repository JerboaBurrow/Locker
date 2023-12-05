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
    crypto::{hash, encrypt, decrypt_string},
    util::{write_file, read_file_utf8, dump_bytes, read_bytes, warning, as_base64, from_base64}, 
    program_version,
    compatible,
    error::{KeyCollisionError, KeyNonExistantError, ReadError, WriteError}, version_compression_added, VERSION_REGEX
};

use regex::Regex;

use semver::Version;

use openssl::sha::Sha256;

use serde::{Deserialize, Serialize};

use std::{collections::HashMap, path::Path};

use std::convert::{From, Into};

use openssl::
{
    rsa::Rsa,
    pkey::Private
};

#[derive(Serialize, Deserialize)]
pub struct Entry0_2_0 
{
    hash: String,
    value: String
}

#[derive(Serialize, Deserialize)]
pub struct Lkr0_2_0
{
    version: String,
    check_hash: String,
    entries: Vec<Entry0_2_0>,
    keys: Vec<String>
}

#[derive(Serialize, Deserialize)]
pub struct Entry 
{
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    hash: Vec<u8>,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    value: Vec<u8>
}

impl From<Entry0_2_0> for Entry 
{
    fn from(uncompressed: Entry0_2_0) -> Self
    {
        Entry 
        { 
            hash: read_bytes(uncompressed.hash), 
            value: uncompressed.value.as_bytes().to_vec()
        }
    }
}

impl Into<Entry0_2_0> for Entry
{
    fn into(self) -> Entry0_2_0
    {
        Entry0_2_0
        { 
            hash: dump_bytes(&self.hash), 
            value: dump_bytes(&self.value)
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Key 
{
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    bytes: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct Lkr
{
    version: String,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    check_hash: Vec<u8>,
    entries: Vec<Entry>,
    keys: Vec<Key>
}

pub struct Locker {
    data: HashMap<[u8; 32], Vec<u8>>,
    keys: Vec<Vec<u8>>
}

#[derive(Serialize, Deserialize)]
pub struct EntryPlainText
{
    pub key: String,
    pub value: String
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

    pub fn index_of(&self, key: &str) -> Option<usize>
    {
        self.keys.iter().position(|x| x == &hash(key).to_vec())
    }

    pub fn insert(&mut self, key: &str, value: &str, rsa: Rsa<Private>, overwrite: bool) -> Result<(), KeyCollisionError>
    {
        let contains_key = self.contains(key);
        if contains_key && !overwrite
        {
            Err(KeyCollisionError {key: key.to_string()})
        }
        else
        {
            if !contains_key { self.keys.push(encrypt(rsa.clone(), key.as_bytes())); }
            let h = hash(key);
            self.data.insert(h, encrypt(rsa, value.as_bytes()));
            Ok(())
        }
    }

    pub fn delete(&mut self, key: &str) -> Result<(), KeyNonExistantError>
    {
        match self.contains(key)
        {
            true => 
            {
                let index = self.index_of(key).unwrap();
                self.data.remove(&hash(&key));
                self.keys.remove(index);
                Ok(())
            },
            false => 
            {
                Err(KeyNonExistantError { key: format!("no key to delete: {}", key) })
            }
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

    pub fn read(&mut self, path: &str) -> Result<(), ReadError>
    {
        let data = match read_file_utf8(path)
        {
            Ok(d) => d,
            Err(e) =>
            {
                return Err(ReadError { why: e.why, file: e.file })
            }
        };

        match data.find("\"version\": [")
        {
            Some(_) => 
            {
                let msg = format!("Incompatible lkr file {}, version 0.1.0, loaded in newer release, {}", path, program_version());
                return Err(ReadError {why: msg, file: path.to_string()})
            },
            None => {}
        }

        let re = Regex::new(VERSION_REGEX).unwrap();
        let file_version = match re.captures(&data)
        {
            Some(c) => Version::parse(c.iter().next().unwrap().unwrap().as_str()).unwrap(),
            None => { return Err(ReadError { why: "No version in .lkr file".to_string(), file: path.to_string() })}
        };

        compatible(file_version.clone());

        let (lkr_entries, lkr_keys, lkr_check_hash) = if file_version >= version_compression_added()
        {
            let lkr: Lkr = match serde_json::from_str(&data)
            {
                Ok(data) => {data},
                Err(why) => 
                {
                    return Err(ReadError{ why: format!("Error while loading lkr file {}: {}", path, why), file: path.to_string()})
                }
            };
            
            (lkr.entries, lkr.keys, lkr.check_hash)
        }
        else 
        {
            let lkr: Lkr0_2_0 = match serde_json::from_str(&data)
            {
                Ok(data) => {data},
                Err(why) => 
                {
                    return Err(ReadError{ why: format!("Error while loading lkr file {}: {}", path, why), file: path.to_string()})
                }
            };

            let mut entries: Vec<Entry> = Vec::new();

            for entry in lkr.entries
            {
                entries.push(entry.into())
            }

            let mut keys: Vec<Key> = Vec::new();

            for k in lkr.keys
            {
                keys.push(Key { bytes: read_bytes(k) });
            }

            (entries, keys, read_bytes(lkr.check_hash))
        };

        let mut check_hash: Sha256 = Sha256::new();

        for entry in lkr_entries
        {

            check_hash.update(&entry.hash);
            check_hash.update(&entry.value);

            match entry.hash.len()
            {
                32 => {/*void*/},
                _ => 
                {
                    let msg = format!("found entry with hash value of incorrect size in {}", path);
                    return Err(ReadError { why: msg, file:path.to_string() })
                }
            };

            self.data.insert(entry.hash.try_into().unwrap(), entry.value);
        }

        for key in lkr_keys
        {
            check_hash.update(&key.bytes);
            self.keys.push(key.bytes);
        }

        if lkr_check_hash != check_hash.finish()
        {
            warning(format!("Computed hash from {} does not match check hash in file, possible manipulation",path).as_str());
        }
        Ok(())

    }

    pub fn write(&self, path: &str) -> Result<(), WriteError>
    {

        if Path::new(path).exists()
        {
            match std::fs::copy(path, format!("{}.bk",path))
            {
                Ok(_) => {},
                Err(why) => {return Err(WriteError{ why: format!("Error when backing up lkr file: {}", why), file: path.to_string()})}
            }
        }

        let mut data: Vec<Entry> = Vec::new();
        let mut keys: Vec<Key> = Vec::new();
        let mut check_hash: Sha256 = Sha256::new();

        for (hash, value) in &self.data 
        {
            check_hash.update(hash);
            check_hash.update(&value);

            data.push(Entry { hash: hash.to_vec(), value: value.to_vec() });
        }

        for key in &self.keys
        {
            keys.push(Key { bytes: key.to_vec() });
            check_hash.update(key);
        }

        let lkr = Lkr
        {
            version: program_version().to_string(), 
            check_hash: check_hash.finish().to_vec(), 
            entries: data,
            keys: keys
        };

        match serde_json::to_string_pretty(&lkr)
        {
            Ok(se) => 
            {
                write_file(path, se.as_bytes())
            },
            Err(why) => 
            {
                return Err(WriteError { why: format!("serde_json serialisation error: {}", why), file: path.to_string() })
            }
        }

        Ok(())
    }
}

