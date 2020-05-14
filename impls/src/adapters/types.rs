//The following is support mqs usage in mwc713
use crate::error::{Error, ErrorKind};
use crate::libwallet::proof::tx_proof::TxProof;

use grin_wallet_config::WalletConfig;

use grin_wallet_libwallet::Slate;
use grinswap::{Context, Message, Swap};
use std::sync::mpsc::{Receiver, Sender};
use url::Url; //only for the Address::parse

use grin_wallet_libwallet::proof::proofaddress::ProvableAddress;
use regex::Regex;
use std::fmt::{self, Debug, Display};

const DEFAULT_MWCMQS_DOMAIN: &str = "mqs.mwc.mw";
pub const DEFAULT_MWCMQS_PORT: u16 = 443;

const ADDRESS_REGEX: &str = r"^((?P<address_type>keybase|mwcmq|mwcmqs|https|http)://).+$";
const KEYBASE_ADDRESS_REGEX: &str = r"^(keybase://)?(?P<username>[0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_]{1,16})(:(?P<topic>[a-zA-Z0-9_-]+))?$";

pub enum CloseReason {
	Normal,
	Abnormal(Error),
}

pub trait Publisher {
	fn post_slate(&self, slate: &Slate, to: &dyn Address) -> Result<(), Error>;
	fn encrypt_slate(&self, slate: &Slate, to: &dyn Address) -> Result<String, Error>;
	fn decrypt_slate(
		&self,
		from: String,
		mapmessage: String,
		signature: String,
		source_address: &ProvableAddress,
	) -> Result<String, Error>;

	fn post_take(&self, message: &Message, to: &str) -> Result<(), Error>;
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
	fn on_message(&mut self, from: &dyn Address, message: Message, config: &WalletConfig);
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
	fn on_message(&mut self, from: &dyn Address, message: Message);
}

//The following is support mqs usage in mwc713

pub trait Address: Debug + Display {
	fn from_str(s: &str) -> Result<Self, Error>
	where
		Self: Sized;
	fn address_type(&self) -> AddressType;
	fn get_stripped(&self) -> String;
	fn get_full_name(&self) -> String;
}

#[derive(Debug, PartialEq)]
pub enum AddressType {
	MWCMQS,
	Keybase,
	Https,
}

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

	fn get_full_name(&self) -> String {
		"keybase://".to_string() + &self.get_stripped()
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

#[derive(Clone, Debug)]
pub struct MWCMQSAddress {
	pub address: ProvableAddress,
	pub domain: String,
	pub port: u16,
}

const MWCMQ_ADDRESS_REGEX: &str = r"^(mwcmqs://)?(?P<public_key>[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{52})(@(?P<domain>[a-zA-Z0-9\.]+)(:(?P<port>[0-9]*))?)?$";

impl MWCMQSAddress {
	pub fn new(address: ProvableAddress, domain: Option<String>, port: Option<u16>) -> Self {
		Self {
			address,
			domain: domain.unwrap_or(DEFAULT_MWCMQS_DOMAIN.to_string()),
			port: port.unwrap_or(DEFAULT_MWCMQS_PORT),
		}
	}
}

impl Display for MWCMQSAddress {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "mwcmqs://{}", self.address.public_key)?;
		if self.domain != DEFAULT_MWCMQS_DOMAIN || self.port != DEFAULT_MWCMQS_PORT {
			write!(f, "@{}", self.domain)?;
			if self.port != DEFAULT_MWCMQS_PORT {
				write!(f, ":{}", self.port)?;
			}
		}
		Ok(())
	}
}

impl Address for MWCMQSAddress {
	/// Extract the address plus additional data
	fn from_str(s: &str) -> Result<Self, Error> {
		let re = Regex::new(MWCMQ_ADDRESS_REGEX).unwrap();
		let captures = re.captures(s);
		if captures.is_none() {
			Err(ErrorKind::MqsGenericError(format!(
				"Unable to parse MWC address {}",
				s
			)))?;
		}

		let captures = captures.unwrap();
		let public_key = captures
			.name("public_key")
			.ok_or(ErrorKind::MqsGenericError(format!(
				"Unable to parse MWC MQS address {}, public key part is not found",
				s
			)))?
			.as_str()
			.to_string();

		let domain = captures.name("domain").map(|m| m.as_str().to_string());
		let port = match captures.name("port") {
			Some(m) => Some(u16::from_str_radix(m.as_str(), 10).map_err(|_| {
				ErrorKind::MqsGenericError(format!("Unable to parse MWC MQS port value"))
			})?),
			None => None,
		};

		Ok(MWCMQSAddress::new(
			ProvableAddress::from_str(&public_key).map_err(|e| {
				ErrorKind::MqsGenericError(format!("Invalid MQS address {}, {}", s, e))
			})?,
			domain,
			port,
		))
	}

	fn get_stripped(&self) -> String {
		format!("{}", self)[9..].to_string()
	}

	fn get_full_name(&self) -> String {
		"mwcmqs://".to_string() + &self.get_stripped()
	}

	fn address_type(&self) -> AddressType {
		AddressType::MWCMQS
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

	fn get_full_name(&self) -> String {
		self.get_stripped()
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
		let re = Regex::new(ADDRESS_REGEX)
			.map_err(|e| ErrorKind::KeybaseGenericError(format!("Unable to construct address parser, {}",e)))?;
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

pub trait ContextHolderType: Send {
	fn get_context(&mut self) -> Option<&Context>;
	fn set_context(&mut self, ctx: Context);
	fn set_swap(&mut self, swap: Swap);
	fn get_swap(&mut self) -> Option<&mut Swap>;
	fn get_objs(&mut self) -> Option<(&Context, &mut Swap)>;
}
