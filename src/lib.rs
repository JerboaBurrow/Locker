pub mod error;
pub mod crypto;
pub mod util;
pub mod file;
pub mod command;
pub mod arguments;

const MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");
const MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");
const PATCH: &str = env!("CARGO_PKG_VERSION_PATCH");

const VERSION_REGEX: &str = r"(\d.){2}\d+";

use semver::{BuildMetadata, Prerelease, Version};
use util::warning;

// making a const Version, &'static or other stuff went to hell
pub fn program_version() -> Version 
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

fn version_compression_added() -> Version
{
    Version 
    { 
        major: 0, 
        minor: 3, 
        patch: 0, 
        pre: Prerelease::EMPTY, 
        build: BuildMetadata::EMPTY 
    }
}

pub fn compatible(file_version: Version)
{
    
    let program = program_version();
    let initial_version = Version::parse("0.1.0").unwrap();

    if file_version != program_version()
    {
        let compat = match program.major > 0
        {
            true => {true},
            false => 
            {
                if program.minor < file_version.minor
                {
                    false
                }
                else if file_version == initial_version && program != initial_version
                {
                    false
                }
                else
                {
                    true
                }
            }
        };

        let compat_info = match compat
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

}