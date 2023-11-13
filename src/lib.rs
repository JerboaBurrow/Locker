pub mod crypto;
pub mod util;
pub mod file;
const MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");
const MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");
const PATCH: &str = env!("CARGO_PKG_VERSION_PATCH");

use semver::{BuildMetadata, Prerelease, Version, VersionReq};

// making a const Version, &'static or other stuff went to hell
fn program_version() -> Version 
{
    Version
    {
        major: MAJOR.parse().unwrap(),
        minor: MINOR.parse().unwrap(),
        patch: PATCH.parse().unwrap(),
        pre: Prerelease::EMPTY,
        build: BuildMetadata::EMPTY
    }
}

pub fn compatible(v: Version, u: Version) -> bool
{
    match v.major > 0
    {
        true => {true},
        false => 
        {
            let initial_version = Version::parse("0.1.0").unwrap();
            if v < initial_version || u < initial_version
            {
                false
            }
            else if v > u && u == initial_version
            {
                false 
            }
            else if u > v && v == initial_version
            {
                false 
            }
            else
            {
                true
            }
        }
    }
}