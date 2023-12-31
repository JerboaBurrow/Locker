use std::fmt;

#[derive(Debug, Clone)]
pub struct ReadError
{
    pub why: String,
    pub file: String
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} while reading lkr file {}", self.why, self.file)
    }
}

#[derive(Debug, Clone)]
pub struct WriteError
{
    pub why: String,
    pub file: String
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} while writing lkr file {}", self.why, self.file)
    }
}

#[derive(Debug, Clone)]
pub struct KeyCollisionError
{
    pub key: String
}

impl fmt::Display for KeyCollisionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "key {}, is already in lkr file", self.key)
    }
}

#[derive(Debug, Clone)]
pub struct KeyNonExistantError
{
    pub key: String
}

impl fmt::Display for KeyNonExistantError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "key, {}, is not in lkr file", self.key)
    }
}

#[derive(Debug, Clone)]
pub struct CommandError
{
    pub why: String
}

pub enum CommandResult {
    OK,
    NothingToDo
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.why)
    }
}

#[derive(Debug, Clone)]
pub struct NoSuchFileError
{
    pub why: String
}

impl fmt::Display for NoSuchFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "file matching, {}, not found in current dir", self.why)
    }
}

#[derive(Debug, Clone)]
pub struct RSAError
{
    pub why: String
}

impl fmt::Display for RSAError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "While building RSA: {}", self.why)
    }
}

#[derive(Debug, Clone)]
pub struct ReadFileError
{
    pub file: String,
    pub why: String
}

impl fmt::Display for ReadFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "While reading file {}: {}", self.file, self.why)
    }
}

#[derive(Debug, Clone)]
pub struct ArgumentError
{
    pub why: String
}

impl fmt::Display for ArgumentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "While reading commandline arguments: {}", self.why)
    }
}

#[derive(Debug, Clone)]
pub struct CompressionError
{
    pub why: String
}

impl fmt::Display for CompressionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.why)
    }
}