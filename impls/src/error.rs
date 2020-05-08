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

//! Implementation specific error types
use crate::core::libtx;
use crate::keychain;
use crate::libwallet;
use crate::util::secp;
use failure::{Backtrace, Context, Fail};
use std::env;
use std::fmt::{self, Display};

/// Error definition
#[derive(Debug)]
pub struct Error {
	pub inner: Context<ErrorKind>,
}

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	/// LibTX Error
	#[fail(display = "LibTx Error, {}", _0)]
	LibTX(libtx::ErrorKind),

	/// LibWallet Error
	#[fail(display = "LibWallet Error, {}", _0)]
	LibWallet(String),

	/// Keychain error
	#[fail(display = "Keychain error, {}", _0)]
	Keychain(keychain::Error),

	/// Error when formatting json
	#[fail(display = "IO error, {}", _0)]
	IO(String),

	/// Secp Error
	#[fail(display = "Secp error, {}", _0)]
	Secp(secp::Error),

	/// Error when formatting json
	#[fail(display = "Serde JSON error, {}", _0)]
	Format(String),

	/// Wallet seed already exists
	#[fail(display = "Wallet seed file exists: {}", _0)]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[fail(display = "Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Wallet seed doesn't exist
	#[fail(display = "Wallet doesn't exist at {}. {}", _0, _1)]
	WalletDoesntExist(String, String),

	/// Enc/Decryption Error
	#[fail(display = "Enc/Decryption error (check password?), {}", _0)]
	Encryption(String),

	/// BIP 39 word list
	#[fail(display = "BIP39 Mnemonic (word list) Error, {}", _0)]
	Mnemonic(String),

	/// Command line argument error
	#[fail(display = "{}", _0)]
	ArgumentError(String),

	/// Generating ED25519 Public Key
	#[fail(display = "Error generating ed25519 secret key: {}", _0)]
	ED25519Key(String),

	/// Checking for onion address
	#[fail(display = "Address is not an Onion v3 Address: {}", _0)]
	NotOnion(String),

	/// API Error
	#[fail(display = "Adapter Callback Error, {}", _0)]
	ClientCallback(String),

	/// Tor Configuration Error
	#[fail(display = "Tor Config Error: {}", _0)]
	TorConfig(String),

	/// Tor Process error
	#[fail(display = "Tor Process Error: {}", _0)]
	TorProcess(String),

	/// Error contacting wallet API
	#[fail(display = "Wallet Communication Error: {}", _0)]
	WalletComms(String),

	/// Listener is closed issue
	#[fail(display = "{} listener is closed! consider using `listen` first.", _0)]
	ClosedListener(String),

	/// MQS generic error
	#[fail(display = "MQS error: {}", _0)]
	MqsGenericError(String),

	/// Keybase generic error
	#[fail(display = "Keybase error: {}", _0)]
	KeybaseGenericError(String),

	/// Get MQS invalid response
	#[fail(display = "{} Sender returned invalid response.", _0)]
	MqsInvalidRespose(String),

	/// Other
	#[fail(display = "Generic error: {}", _0)]
	GenericError(String),

	#[fail(display = "unkown address!, {}", _0)]
	UnknownAddressType(String),

	#[fail(display = "could not parse `{}` to a keybase address!", 0)]
	KeybaseAddressParsingError(String),

	#[fail(display = "could not parse `{}` to a https address!", 0)]
	HttpsAddressParsingError(String),
}

impl Fail for Error {
	fn cause(&self) -> Option<&dyn Fail> {
		self.inner.cause()
	}

	fn backtrace(&self) -> Option<&Backtrace> {
		self.inner.backtrace()
	}
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let show_bt = match env::var("RUST_BACKTRACE") {
			Ok(r) => {
				if r == "1" {
					true
				} else {
					false
				}
			}
			Err(_) => false,
		};
		let backtrace = match self.backtrace() {
			Some(b) => format!("{}", b),
			None => String::from("Unknown"),
		};
		let inner_output = format!("{}", self.inner,);
		let backtrace_output = format!("\nBacktrace: {}", backtrace);
		let mut output = inner_output.clone();
		if show_bt {
			output.push_str(&backtrace_output);
		}
		Display::fmt(&output, f)
	}
}

impl Error {
	/// get kind
	pub fn kind(&self) -> ErrorKind {
		self.inner.get_context().clone()
	}
	/// get cause
	pub fn cause(&self) -> Option<&dyn Fail> {
		self.inner.cause()
	}
	/// get backtrace
	pub fn backtrace(&self) -> Option<&Backtrace> {
		self.inner.backtrace()
	}
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

impl From<Context<ErrorKind>> for Error {
	fn from(inner: Context<ErrorKind>) -> Error {
		Error { inner: inner }
	}
}

impl From<keychain::Error> for Error {
	fn from(error: keychain::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Keychain(error)),
		}
	}
}

impl From<secp::Error> for Error {
	fn from(error: secp::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Secp(error)),
		}
	}
}

impl From<libwallet::Error> for Error {
	fn from(error: libwallet::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::LibWallet(format!("{}", error))),
		}
	}
}

impl From<libtx::Error> for Error {
	fn from(error: libtx::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::LibTX(error.kind())),
		}
	}
}
