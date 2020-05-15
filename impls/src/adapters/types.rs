//The following is support mqs usage in mwc713
use super::mwcmq::MWCMQSAddress;
use crate::error::ErrorKind;
use crate::libwallet::proof::tx_proof::TxProof;
use failure::Error;
use grin_wallet_libwallet::Slate;
use std::sync::mpsc::{Receiver, Sender};
use url::Url; //only for the Address::parse

use regex::Regex;
use std::fmt::{self, Debug, Display};
const ADDRESS_REGEX: &str = r"^((?P<address_type>keybase|mwcmq|mwcmqs|https|http)://).+$";
const KEYBASE_ADDRESS_REGEX: &str = r"^(keybase://)?(?P<username>[0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_]{1,16})(:(?P<topic>[a-zA-Z0-9_-]+))?$";

pub enum CloseReason {
	Normal,
	Abnormal(Error),
}

pub trait Publisher {
	fn post_slate(&self, slate: &Slate, to: &dyn Address) -> Result<(), Error>;
}

pub trait Subscriber {
	fn start(&mut self) -> Result<(), Error>;
	fn stop(&mut self) -> bool;
	fn is_running(&self) -> bool;

	fn set_notification_channels(
		&self,
		slate_send_channel: Sender<Slate>,
		message_receive_channel: Receiver<bool>,
	);
	fn reset_notification_channels(&self);
}

pub trait SubscriptionHandler: Send {
	fn on_open(&self);
	fn on_slate(&self, from: &dyn Address, slate: &mut Slate, proof: Option<&mut TxProof>);
	fn on_close(&self, result: CloseReason);
	fn on_dropped(&self);
	fn on_reestablished(&self);

	fn set_notification_channels(
		&self,
		slate_send_channel: Sender<Slate>,
		message_receive_channel: Receiver<bool>,
	);
	fn reset_notification_channels(&self);
}

//The following is support mqs usage in mwc713

pub trait Address: Debug + Display {
	fn from_str(s: &str) -> Result<Self, Error>
	where
		Self: Sized;
	fn address_type(&self) -> AddressType;
	fn get_stripped(&self) -> String;
}

#[derive(Debug, PartialEq)]
pub enum AddressType {
	MWCMQS,
	Keybase,
	Https,
}

///============the following is to support mwc713 usage
/// we would like to also merge the keybase code in both wallets in the future.

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeybaseAddress {
	pub username: String,
	pub topic: Option<String>,
}

impl Address for KeybaseAddress {
	fn from_str(s: &str) -> Result<Self, Error> {
		let re = Regex::new(KEYBASE_ADDRESS_REGEX).unwrap();
		let captures = re.captures(s);
		if captures.is_none() {
			Err(ErrorKind::KeybaseAddressParsingError(s.to_string()))?;
		}

		let captures = captures.unwrap();
		let username = captures.name("username").unwrap().as_str().to_string();
		let topic = captures.name("topic").map(|m| m.as_str().to_string());
		Ok(Self { username, topic })
	}

	fn address_type(&self) -> AddressType {
		AddressType::Keybase
	}

	fn get_stripped(&self) -> String {
		format!("{}", self.username)
	}
}

impl Display for KeybaseAddress {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "keybase://{}", self.username)?;
		if let Some(ref topic) = self.topic {
			write!(f, ":{}", topic)?;
		}
		Ok(())
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpsAddress {
	pub uri: String,
}

impl Address for HttpsAddress {
	fn from_str(s: &str) -> Result<Self, Error> {
		Url::parse(s).map_err(|_| ErrorKind::HttpsAddressParsingError(s.to_string()))?;

		Ok(Self { uri: s.to_string() })
	}

	fn address_type(&self) -> AddressType {
		AddressType::Https
	}

	fn get_stripped(&self) -> String {
		self.uri.clone()
	}
}

impl Display for HttpsAddress {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.uri)?;
		Ok(())
	}
}

impl dyn Address {
	pub fn parse(address: &str) -> Result<Box<dyn Address>, Error> {
		let re = Regex::new(ADDRESS_REGEX)?;
		let captures = re.captures(address);
		if captures.is_none() {
			return Ok(Box::new(MWCMQSAddress::from_str(address)?));
		}

		let captures = captures.unwrap();
		let address_type = captures.name("address_type").unwrap().as_str().to_string();
		let address: Box<dyn Address> = match address_type.as_ref() {
			"keybase" => Box::new(KeybaseAddress::from_str(address)?),
			"mwcmqs" => Box::new(MWCMQSAddress::from_str(address)?),
			"https" => Box::new(HttpsAddress::from_str(address)?),
			"http" => Box::new(HttpsAddress::from_str(address)?),
			x => Err(ErrorKind::UnknownAddressType(x.to_string()))?,
		};
		Ok(address)
	}
}
