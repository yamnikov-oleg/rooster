// Copyright 2014-2017 The Rooster Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod v1;
pub mod v2;

use std::io::{Error as IoError, stdin, Write};
use std::ops::Deref;
use std::convert::From;
use safe_string::SafeString;
use safe_vec::SafeVec;

#[derive(Debug)]
pub enum PasswordError {
    DecryptionError,
    EncryptionError,
    NoSuchAppError,
    AppExistsError,
    Io(IoError),
    WrongVersionError,
    InvalidJsonError,
    CorruptionError,
}

impl From<IoError> for PasswordError {
    fn from(err: IoError) -> PasswordError {
        PasswordError::Io(err)
    }
}

fn upgrade_v1_v2(v1_passwords: &[v1::Password],
                 v2_store: &mut v2::PasswordStore)
                 -> Result<(), PasswordError> {
    for p in v1_passwords.iter() {
        let v2_password = v2::Password {
            name: p.name.clone(),
            username: p.username.clone(),
            password: p.password.clone(),
            created_at: p.created_at,
            updated_at: p.updated_at,
        };
        v2_store.add_password(v2_password)?;
    }

    Ok(())
}

pub fn upgrade(master_password: SafeString,
               input: SafeVec)
               -> Result<v2::PasswordStore, PasswordError> {
    // If we can't read v1 passwords, we have a hard error, because we previously tried
    // to read the passwords as v2. Which failed. That means we can't upgrade.
    let v1_passwords = v1::get_all_passwords(master_password.deref(), input.deref())?;

    println_stderr!("Your Rooster file has version 1. You need to upgrade to version 2.");
    println_stderr!("");
    println_stderr!("WARNING: If in doubt, it could mean you've been hacked. Only");
    println_stderr!("proceed if you recently upgraded your Rooster installation.");
    println_stderr!("");
    println_stderr!("Upgrade to version 2? [y/n]");
    loop {
        let mut line = String::new();
        match stdin().read_line(&mut line) {
            Ok(_) => {
                if line.starts_with('y') {
                    break;
                } else if line.starts_with('n') {
                    return Err(PasswordError::WrongVersionError);
                } else {
                    println_stderr!("I did not get that. Upgrade from v1 to v2? [y/n]");
                }
            }
            Err(io_err) => {
                return Err(PasswordError::Io(io_err));
            }
        }
    }

    // Upgrade from v1 to v2 if we could read v1 passwords.
    let mut v2_store = v2::PasswordStore::new(master_password.clone())?;
    upgrade_v1_v2(v1_passwords.deref(), &mut v2_store)?;

    Ok(v2_store)
}
