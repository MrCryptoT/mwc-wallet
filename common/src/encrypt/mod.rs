#[macro_use]
mod polyfill;

pub mod aead;

pub mod constant_time;
pub mod error;

mod c;
mod chacha;
mod init;
mod poly1305;
