pub mod error;
pub mod crypto;
pub mod util;
pub mod file;
pub mod command;

const MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");
const MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");
const PATCH: &str = env!("CARGO_PKG_VERSION_PATCH");

use semver::{BuildMetadata, Prerelease, Version};

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

pub fn compatible(this: Version, with: Version) -> bool
{
    match this.major > 0
    {
        true => {true},
        false => 
        {
            if this.minor > with.minor
            {
                return false
            }

            let initial_version = Version::parse("0.1.0").unwrap();
            return if this < initial_version || with < initial_version
            {
                false
            }
            else if this > with && with == initial_version
            {
                false 
            }
            else if with > this && this == initial_version
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