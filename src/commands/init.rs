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

use getopts;
use password;
use rpassword::prompt_password_stderr;
use safe_string::SafeString;
use clip::{copy_to_clipboard, paste_keys};
use std::io::Write;
use std::ops::Deref;
use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;
use std::env;
use std::path::{Path, PathBuf};

const DONT_CREATE_PASSWORD_FILE: &'static str = "DONT_CREATE_PASSWORD_FILE";
const FAIL_READING_NEW_PASSWORD: &'static str = "FAIL_READING_NEW_PASSWORD";

// Look for Dropbox folder.
//
// If you want support for other cloud services, please open an issue
// and we'll see if we can add support for it.
//
// TODO: This is naive implementation that only works properly with the
// default "$HOME/Dropbox" folder. But if you use custom Dropbox folder
// locations, then Rooster doesn't know what to do. It is possible to
// programatically know where Dropbox stores files:
// https://www.dropbox.com/help/4584
fn get_dropbox_folder() -> Option<PathBuf> {
    match env::home_dir() {
        Some(mut dropbox_folder) => {
            dropbox_folder.push("Dropbox");

            if dropbox_folder.exists() {
                Some(dropbox_folder)
            } else {
                None
            }
        }
        None => None,
    }
}

pub fn callback_help() {
    println!("Usage:");
    println!("    rooster init -h");
    println!("    rooster init");
    println!("");
    println!("Example:");
    println!("    rooster init");
}

pub fn callback_exec(matches: &getopts::Matches) -> Result<(), i32> {
    let app_name = matches.free[1].clone();
    let username = matches.free[2].clone();

    // let mut show_default_no_file_msg = true;
    //
    // if let Some(dropbox_folder) = get_dropbox_folder() {
    //     let mut file_in_dropbox = dropbox_folder.clone();
    //     file_in_dropbox.push(ROOSTER_FILE_DEFAULT);
    //
    //     if file_in_dropbox.exists() {
    //         println_title!("|---------------- Dropbox ---------------|");
    //         println_stderr!("");
    //         println_stderr!("Seems like you have a Rooster file in your Dropbox \
    //                          folder.");
    //         println_stderr!("");
    //         println_stderr!("It is located at: ~/Dropbox/{}.",
    //                         ROOSTER_FILE_DEFAULT);
    //
    //         println_stderr!("");
    //         print_stderr!("Is that your correct password file (y/n)? ");
    //         let mut line = String::new();
    //         std::io::stdin().read_line(&mut line)?;
    //         if line.starts_with('y') {
    //             println_stderr!("");
    //             println_title!("|------------- Configuration ------------|");
    //             println_stderr!("");
    //             println_stderr!("You might want to add this to your shell config \
    //                              (.bashrc, .zshrc, etc):");
    //             println_stderr!("    export ROOSTER_FILE={}",
    //                             file_in_dropbox.to_string_lossy());
    //             println_stderr!("");
    //             println_stderr!("This way, I won't ask you if this is the right \
    //                              file every time.");
    //
    //             println_stderr!("");
    //             return get_password_file(file_in_dropbox
    //                                          .to_string_lossy()
    //                                          .as_ref(),
    //                                      true);
    //         }
    //
    //         show_default_no_file_msg = false;
    //         println_stderr!("");
    //         println_title!("|----------- New password file ----------|");
    //         println_stderr!("");
    //         print_stderr!("OK. Would you like to create a new \
    //                          password file now (y/n)? ");
    //     }
    // }
    //
    // loop {
    //     if show_default_no_file_msg {
    //         println_title!("|----------- New password file ----------|");
    //         println_stderr!("");
    //         println_stderr!("I can't find your password file. This is expected \
    //                          if you are using Rooster for the first time.");
    //         println_stderr!("");
    //         print_stderr!("Would you like to create a password file now (y/n)? ");
    //     }
    //
    //     let mut line = String::new();
    //     std::io::stdin().read_line(&mut line)?;
    //     if line.starts_with('y') {
    //         println_stderr!("");
    //         println_stderr!("Alright, will do! But first, there is some stuff we \
    //                          have to take care of.");
    //         println_stderr!("");
    //         println_title!("|---------- Set Master Password ---------|");
    //         println_stderr!("");
    //         println_stderr!("In order to keep your passwords safe & \
    //                          secure, we encrypt them using a Master \
    //                          Password.");
    //         println_stderr!("");
    //         println_stderr!("The stronger it is, the better your passwords are \
    //                          protected.");
    //         println_stderr!("");
    //
    //         let master_password = prompt_password_stderr("What would you like it \
    //                                                       to be? ");
    //         let master_password = master_password
    //             .map(SafeString::new)
    //             .map_err(|_| {
    //                          IoError::new(IoErrorKind::Other,
    //                                       FAIL_READING_NEW_PASSWORD)
    //                      })?;
    //
    //         let mut filename = filename.to_owned();
    //
    //         // Maybe the user wants their Rooster file in Dropbox.
    //         if let Some(folder) = get_dropbox_folder() {
    //             println_stderr!("");
    //             println_title!("|---------------- Dropbox ---------------|");
    //
    //             println_stderr!("");
    //             println_stderr!("Seems like you're using Dropbox.");
    //
    //             println_stderr!("");
    //             print_stderr!("Would you like to add your password file to \
    //                            Dropbox (y/n)? ");
    //             let mut line = String::new();
    //             std::io::stdin().read_line(&mut line)?;
    //             if line.starts_with('y') {
    //                 filename = format!("{}/{}",
    //                                    folder.to_string_lossy(),
    //                                    ROOSTER_FILE_DEFAULT);
    //
    //                 println_stderr!("");
    //                 println_title!("|------------- Configuration ------------|");
    //                 println_stderr!("");
    //                 println_stderr!("You'll need to add this to your shell \
    //                                  config (.bashrc, .zshrc, etc):");
    //                 println_stderr!("    export ROOSTER_FILE={}", filename);
    //
    //                 if let Some(previous) = env::var(ROOSTER_FILE_ENV_VAR).ok() {
    //                     println_stderr!("");
    //                     println_stderr!("You'll also need to delete your \
    //                                      previous Rooster file configuration. It \
    //                                      probably looks something like this:");
    //                     println_stderr!("    export ROOSTER_FILE={}", previous);
    //                 }
    //             }
    //         }
    //
    //         let password_file = open_password_file(filename.as_str(), true)?;
    //
    //         println_stderr!("");
    //         println_title!("|---- All set! Running Rooster now... ---|");
    //         println_stderr!("");
    //
    //         return Ok((Some(master_password), password_file));
    //     } else if line.starts_with('n') {
    //         return Err(IoError::new(IoErrorKind::Other, DONT_CREATE_PASSWORD_FILE));
    //     } else {
    //         println_stderr!("I didn't get that. Should I create a password file \
    //                          now (y/n)? ");
    //     }
    // }

    Ok(())
}
