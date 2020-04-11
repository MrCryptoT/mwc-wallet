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

mod file;
pub mod http;
mod keybase;

pub use self::file::PathToSlate;
pub use self::http::{HttpSlateSender, SchemeNotHttp};
pub use self::keybase::{KeybaseAllChannels, KeybaseChannel};

use crate::config::{TorConfig, WalletConfig};
use crate::libwallet::{Error, ErrorKind, Slate};
use crate::tor::config::complete_tor_address;
use crate::util::ZeroingString;

//todo Yang may need to move to other places.
use crate::util::Mutex;
use grin_wallet_mwcmqs::mwcmq::MWCMQPublisher;
use grin_wallet_mwcmqs::mwcmq::MWCMQSubscriber;
use grin_wallet_mwcmqs::mwcmq::Publisher;
use grin_wallet_mwcmqs::types::Address;
use grin_wallet_mwcmqs::types::MWCMQSAddress;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

/// Sends transactions to a corresponding SlateReceiver
pub trait SlateSender {
	/// Send a transaction slate to another listening wallet and return result
	/// TODO: Probably need a slate wrapper type
	fn send_tx(&self, slate: &Slate) -> Result<Slate, Error>;
}

pub trait SlateReceiver {
	/// Start a listener, passing received messages to the wallet api directly
	/// Takes a wallet config for now to avoid needing all sorts of awkward
	/// type parameters on this trait
	fn listen(
		&self,
		config: WalletConfig,
		passphrase: ZeroingString,
		account: &str,
		node_api_secret: Option<String>,
	) -> Result<(), Error>;
}

/// Posts slates to be read later by a corresponding getter
pub trait SlatePutter {
	/// Send a transaction asynchronously
	fn put_tx(&self, slate: &Slate) -> Result<(), Error>;
}

/// Checks for a transaction from a corresponding SlatePutter, returns the transaction if it exists
pub trait SlateGetter {
	/// Receive a transaction async. (Actually just read it from wherever and return the slate)
	fn get_tx(&self) -> Result<Slate, Error>;
}

/// select a SlateSender based on method and dest fields from, e.g., SendArgs
pub fn create_sender(
	method: &str,
	dest: &str,
	apisecret: &Option<String>,
	tor_config: Option<TorConfig>,
	mqs_channel: Option<MwcMqsChannel>,
) -> Result<Box<dyn SlateSender>, Error> {
	let invalid = || {
		ErrorKind::WalletComms(format!(
			"Invalid wallet comm type and destination. method: {}, dest: {}",
			method, dest
		))
	};

	let mut method = method.into();

	// will test if this is a tor address and fill out
	// the http://[].onion if missing
	let dest = match complete_tor_address(dest) {
		Ok(d) => {
			method = "tor";
			d
		}
		Err(_) => dest.into(),
	};

	Ok(match method {
		"http" => Box::new(HttpSlateSender::new(&dest, apisecret.clone()).map_err(|_| invalid())?),
		"tor" => match tor_config {
			None => {
				return Err(
					ErrorKind::WalletComms("Tor Configuration required".to_string()).into(),
				);
			}
			Some(tc) => Box::new(
				HttpSlateSender::with_socks_proxy(
					&dest,
					apisecret.clone(),
					&tc.socks_proxy_addr,
					&tc.send_config_dir,
				)
				.map_err(|_| invalid())?,
			),
		},
		"keybase" => Box::new(KeybaseChannel::new(dest.to_owned())?),
		"mwcmqs" => Box::new(mqs_channel.unwrap()),
		"self" => {
			return Err(ErrorKind::WalletComms(
				"No sender implementation for \"self\".".to_string(),
			)
			.into());
		}
		"file" => {
			return Err(ErrorKind::WalletComms(
				"File based transactions must be performed asynchronously.".to_string(),
			)
			.into());
		}
		_ => {
			return Err(ErrorKind::WalletComms(format!(
				"Wallet comm method \"{}\" does not exist.",
				method
			))
			.into());
		}
	})
}

//===============add with mwcmqs feature=============
//may need to move to other place later
pub struct MwcMqsChannel {
	mwcmqs_broker: Arc<Mutex<Option<(MWCMQPublisher, MWCMQSubscriber)>>>,
	rx: Arc<Mutex<Option<Receiver<Box<Slate>>>>>,
	tx: Arc<Mutex<Option<Sender<Box<bool>>>>>,
	des_address: String,
	finalize: bool,
}

impl MwcMqsChannel {
	pub fn new(
		mwcmqs_broker: Arc<Mutex<Option<(MWCMQPublisher, MWCMQSubscriber)>>>,
		rx_withlock: Arc<Mutex<Option<Receiver<Box<Slate>>>>>,
		tx_withlock: Arc<Mutex<Option<Sender<Box<bool>>>>>,
		des_address: String,
		finalize: bool,
	) -> Self {
		Self {
			mwcmqs_broker: mwcmqs_broker,
			rx: rx_withlock,
			des_address: des_address,
			tx: tx_withlock,
			finalize: finalize,
		}
	}
}

impl SlateSender for MwcMqsChannel {
	fn send_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		let mwcmqs_broker_lock = self.mwcmqs_broker.lock();
		let tx_lock = self.tx.lock();
		//notify the mqs thread to do finalizing and proof.
		if let Some(i) = &*tx_lock {
			i.send(Box::new(self.finalize));
		}

		if let Some(i) = &*mwcmqs_broker_lock {
			let mwcmqs_publisher = &i.0;
			let des_address = MWCMQSAddress::from_str(self.des_address.as_ref());
			if des_address.is_ok() {
				let des_address = des_address.unwrap();
				let _res = mwcmqs_publisher.post_slate(&slate, &des_address);
			}
		} else {
			return Err(ErrorKind::ClientCallback(
				"mqs is not started, not able to send the request".to_owned(),
			)
			.into());
		}

		//expect to get the ok message
		let rx_withlock = self.rx.lock();
		if let Some(i) = &*rx_withlock {
			let rx = &i;
			let slate_returned = rx.recv_timeout(Duration::from_secs(30));
			match slate_returned {
				Ok(s) => {
					return Ok(*s);
				}
				_ => {
					return Err(ErrorKind::ClientCallback(
						"request timeout, please use txs api to check the status".to_owned(),
					)
					.into())
				}
			}
		}
		return Err(Error::from(ErrorKind::GrinWalletMwcMqsGeneralError));
	}
}
