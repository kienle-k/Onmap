use std::env;
use std::process::Command;

fn main() {
    println!(
        "cargo:rustc-env=ONMAP_GIT_COMMIT={}",
        git_stdout(&["rev-parse", "HEAD"]).unwrap_or("unknown".to_string())
    );
    println!(
        "cargo:rustc-env=ONMAP_GIT_DESCRIBE={}",
        git_stdout(&["describe", "--tags", "--dirty", "--always"]).unwrap_or("unknown".to_string())
    );
    println!(
        "cargo:rustc-env=ONMAP_GIT_DIRTY={}",
        git_dirty().unwrap_or("null".to_string())
    );
    println!(
        "cargo:rustc-env=ONMAP_BUILD_PROFILE={}",
        env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string())
    );
}

fn git_stdout(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;

    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();

    if value.is_empty() {
        return None;
    }

    Some(value.to_string())
}

fn git_dirty() -> Option<String> {
    let output = Command::new("git")
        .args(["diff", "--quiet", "--ignore-submodules", "HEAD", "--"])
        .status()
        .ok()?;

    match output.code() {
        Some(0) => Some("false".to_string()),
        Some(1) => Some("true".to_string()),
        _ => None,
    }
}
