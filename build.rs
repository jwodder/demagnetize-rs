use std::process::ExitCode;
use thiserror::Error;

fn main() -> ExitCode {
    let (major, minor, patch) = match get_version_bits() {
        Ok(bits) => bits,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let mut prefix = String::from("-DM-");
    prefix.push_str(&major);
    if minor.len() < 2 {
        prefix.push('0');
    }
    prefix.push_str(&minor);
    prefix.push_str(&patch);
    prefix.push('-');
    println!("cargo::rustc-env=PEER_ID_PREFIX={prefix}");
    ExitCode::SUCCESS
}

fn get_version_bits() -> Result<(String, String, String), GetEnvError> {
    let major = getenv("CARGO_PKG_VERSION_MAJOR")?;
    let minor = getenv("CARGO_PKG_VERSION_MINOR")?;
    let patch = getenv("CARGO_PKG_VERSION_PATCH")?;
    Ok((major, minor, patch))
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{varname} envvar not set: {source}")]
struct GetEnvError {
    varname: &'static str,
    source: std::env::VarError,
}

fn getenv(varname: &'static str) -> Result<String, GetEnvError> {
    std::env::var(varname).map_err(|source| GetEnvError { varname, source })
}
