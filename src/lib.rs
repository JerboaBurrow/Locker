pub mod crypto;
pub mod util;
pub mod file;

const MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");
const MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");
const PATCH: &str = env!("CARGO_PKG_VERSION_PATCH");

#[derive(Clone, PartialEq, Eq)]
pub struct Version 
{
    major: String,
    minor: String,
    patch: String,
    modifier: String
}

// making a const Version, &'static or other stuff went to hell
fn program_version() -> Version 
{
    Version
    {
        major: MAJOR.to_string(),
        minor: MINOR.to_string(),
        patch: PATCH.to_string(),
        modifier: "".to_string()
    }
}


pub fn compatible(v: Version, u: Version) -> bool
{
    true
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.patch.as_str()
        {
            "" => {write!(f, "{}.{}.{}",self.major, self.minor, self.patch)}
            _ => {write!(f, "{}.{}.{}-{}",self.major, self.minor, self.patch, self.modifier)}
        }
        
    }
}