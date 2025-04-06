use base64::prelude::*;
use std::env;
use std::os::unix::process::CommandExt;
use std::process::Command;

mod keys;
mod ssh_auth;

fn main() {
    let args = parse_args();
    let username = username();

    if !args.test {
        let mut gitolite_shell = Command::new(args.shell_path);
        if let Some(username) = &username {
            gitolite_shell.arg(username);
        }

        // TODO: Log this error somewhere.
        let _err = gitolite_shell.exec();
    } else if let Some(username) = &username {
        println!("{}", username);
    }
}

struct Args {
    test: bool,
    shell_path: String,
}

enum ParseArgsState {
    None,
    ShellPath,
}

fn parse_args() -> Args {
    let mut result = Args {
        test: false,
        shell_path: String::from("gitolite-shell"),
    };

    let mut state = ParseArgsState::None;
    for arg in env::args() {
        match state {
            ParseArgsState::None => {
                if arg == "-t" || arg == "--test" {
                    result.test = true;
                } else if arg == "-s" || arg == "--shell" {
                    state = ParseArgsState::ShellPath;
                }
            }
            ParseArgsState::ShellPath => {
                let trimmed = arg.trim();
                if trimmed.len() == arg.len() {
                    result.shell_path = arg;
                } else if !trimmed.is_empty() {
                    result.shell_path = String::from(trimmed);
                }
                state = ParseArgsState::None;
            }
        }
    }

    result
}

fn username() -> Option<String> {
    let path = match env::var("SSH_USER_AUTH") {
        Ok(path) => path,
        Err(_) => {
            return None;
        }
    };

    let content = match std::fs::read(path) {
        Ok(content) => content,
        Err(_) => {
            return None;
        }
    };

    let result = ssh_auth::parse_user_auth(&content)?;
    if !keys::is_supported_key_type(&content[result.key_type]) {
        return None;
    }

    // TODO: Find a way to have the key decoded in-place.
    //       The base64_simd crate has such a function, but the API is not great.
    //       See also https://github.com/marshallpierce/rust-base64/issues/190
    let mut key = Vec::with_capacity(result.key.len());
    if BASE64_STANDARD
        .decode_vec(&content[result.key], &mut key)
        .is_err()
    {
        return None;
    }

    keys::find_user_name(&key).unwrap_or(None)
}
