// Copyright 2019 The Grin Developers
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

//! Crate wrapping up the Grin binary and configuration file

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

#[allow(missing_docs)]
pub mod backend;
mod base58;
#[allow(missing_docs)]
pub mod crypto;
mod encrypt;
#[allow(missing_docs)]
mod error_kind;
#[allow(missing_docs)]
pub mod hasher;
#[allow(missing_docs)]
pub mod message;
#[allow(missing_docs)]
pub mod mwcmq;
#[allow(missing_docs)]
pub mod tx_proof;
#[allow(missing_docs)]
pub mod types;

///
pub const COLORED_PROMPT: &'static str = "\x1b[36mwallet713>\x1b[0m ";

pub use self::error_kind::ErrorKind;
pub use failure::Error;
pub use parking_lot::{Mutex, MutexGuard};
pub use std::sync::Arc;
