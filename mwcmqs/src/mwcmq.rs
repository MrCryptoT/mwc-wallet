extern crate nanoid;
extern crate reqwest;

use ws::{Error as WsError, ErrorKind as WsErrorKind};

use std::io::Read;
use std::path::PathBuf;

use super::COLORED_PROMPT;
use super::{Arc, ErrorKind, Mutex};
use crate::crypto::public_key_from_secret_key;
use crate::crypto::sign_challenge;
use crate::crypto::Hex;
use crate::crypto::SecretKey;
use crate::message::EncryptedMessage;
use crate::tx_proof::TxProof;
use crate::types::{Address, GrinboxAddress, MWCMQSAddress, DEFAULT_MWCMQS_PORT};
use colored::Colorize;
use failure::Error;
use grin_wallet_config::WalletConfig;
use grin_wallet_libwallet::Slate;
use grin_wallet_util::grin_core::global::ChainTypes;
use grin_wallet_util::grin_util::secp::key::PublicKey;
use regex::Regex;
use std::collections::HashMap;
use std::time::Duration;
use std::{thread, time};

#[derive(Deserialize, Debug, Clone)]
pub struct MQSConfig {
	pub wallet_data_path: String,
	mwcmqs_domain: String,
	mwcmqs_port: u16,
	pub mwcmqs_key: Option<SecretKey>,
	mwc_node_uri: Option<String>,
	mwc_node_secret: Option<String>,
	config_home: Option<String>,
	chain: ChainTypes,
}

impl MQSConfig {
	pub fn default(config: &WalletConfig) -> MQSConfig {
		MQSConfig {
			wallet_data_path: config.wallet_data_dir.clone().unwrap_or(".".to_string()),
			mwcmqs_domain: config
				.mwcmqs_domain
				.clone()
				.unwrap_or("mqs.mwc.mw".to_string()),
			mwcmqs_port: config.mwcmqs_port.clone().unwrap_or(443),
			mwcmqs_key: None,
			mwc_node_uri: None,
			mwc_node_secret: None,
			config_home: None,
			chain: config.chain_type.clone().unwrap_or(ChainTypes::Mainnet),
		}
	}

	//	fn default_secret_key (config: &WalletConfig) -> SecretKey {
	//		let index = config.grinbox_address_index;
	//		let key = wallet.lock().derive_address_key(index)?;
	//		return key;
	//	}
	pub fn mwcmqs_domain(&self) -> String {
		format!("mqs.mwc.mw")
	}

	pub fn mwcmqs_port(&self) -> u16 {
		443
	}

	pub fn mwc_node_uri(&self) -> String {
		let chain_type = self.chain.clone();
		self.mwc_node_uri.clone().unwrap_or(match chain_type {
			ChainTypes::Mainnet => String::from("https://mwc713.mwc.mw"),
			_ => String::from("https://mwc713.floonet.mwc.mw"),
		})
	}

	pub fn mwc_node_secret(&self) -> Option<String> {
		let _chain_type = self.chain.clone();
		match self.mwc_node_uri {
			Some(_) => self.mwc_node_secret.clone(),
			None => Some(String::from("11ne3EAUtOXVKwhxm84U")),
		}
	}

	// mwc-wallet using top level dir + data dir. We need to follow it
	pub fn get_top_level_directory(&self) -> Result<String, Error> {
		let dir = String::from(self.get_data_path()?.parent().unwrap().to_str().unwrap());
		Ok(dir)
	}

	// mwc-wallet using top level dir + data dir. We need to follow it
	pub fn get_wallet_data_directory(&self) -> Result<String, Error> {
		let wallet_dir = String::from(self.get_data_path()?.file_name().unwrap().to_str().unwrap());
		Ok(wallet_dir)
	}

	pub fn get_data_path_str(&self) -> Result<String, Error> {
		let path_str = self.get_data_path()?.to_str().unwrap().to_owned();
		Ok(path_str)
	}

	pub fn get_data_path(&self) -> Result<PathBuf, Error> {
		let mut data_path = PathBuf::new();
		data_path.push(self.wallet_data_path.clone());
		if data_path.is_absolute() {
			return Ok(data_path);
		}

		let mut data_path = PathBuf::new();
		data_path.push(self.config_home.clone().unwrap());
		data_path.pop();
		data_path.push(self.wallet_data_path.clone());
		Ok(data_path)
	}

	pub fn get_mwcmqs_address(&self) -> Result<MWCMQSAddress, Error> {
		let public_key = self.get_mwcmqs_public_key()?;
		Ok(MWCMQSAddress::new(
			public_key,
			Some(self.mwcmqs_domain()),
			Some(self.mwcmqs_port()),
		))
	}

	pub fn get_mwcmqs_public_key(&self) -> Result<PublicKey, Error> {
		public_key_from_secret_key(&self.get_mwcmqs_secret_key()?)
	}

	pub fn get_mwcmqs_secret_key(&self) -> Result<SecretKey, Error> {
		self.mwcmqs_key
			.clone()
			.ok_or_else(|| ErrorKind::NoWallet.into())
	}
}

pub enum CloseReason {
	Normal,
	Abnormal(Error),
}

pub trait Publisher {
	fn post_slate(&self, slate: &Slate, to: &dyn Address) -> Result<(), Error>;
}

pub trait Subscriber {
	fn start(&mut self, handler: Box<dyn SubscriptionHandler + Send>) -> Result<(), Error>;
	fn stop(&mut self) -> bool;
	fn is_running(&self) -> bool;
}

pub trait SubscriptionHandler: Send {
	fn on_open(&self);
	fn on_slate(
		&self,
		from: &dyn Address,
		slate: &mut Slate,
		proof: Option<&mut TxProof>,
		_: Option<MQSConfig>,
	);
	fn on_close(&self, result: CloseReason);
	fn on_dropped(&self);
	fn on_reestablished(&self);
}

const TIMEOUT_ERROR_REGEX: &str = r"timed out";

#[derive(Clone)]
pub struct MWCMQPublisher {
	address: MWCMQSAddress,
	broker: MWCMQSBroker,
	secret_key: SecretKey,
	config: MQSConfig,
}

impl MWCMQPublisher {
	pub fn new(
		address: &MWCMQSAddress,
		secret_key: &SecretKey,
		config: &MQSConfig,
	) -> Result<Self, Error> {
		Ok(Self {
			address: address.clone(),
			broker: MWCMQSBroker::new(config.clone())?,
			secret_key: secret_key.clone(),
			config: config.clone(),
		})
	}
}

impl Publisher for MWCMQPublisher {
	fn post_slate(&self, slate: &Slate, to: &dyn Address) -> Result<(), Error> {
		let to = MWCMQSAddress::from_str(&to.to_string())?;
		self.broker
			.post_slate(slate, &to, &self.address, &self.secret_key)?;
		Ok(())
	}
}

#[derive(Clone)]
pub struct MWCMQSubscriber {
	address: MWCMQSAddress,
	broker: MWCMQSBroker,
	secret_key: SecretKey,
	config: MQSConfig,
}

impl MWCMQSubscriber {
	pub fn new(publisher: &MWCMQPublisher) -> Result<Self, Error> {
		Ok(Self {
			address: publisher.address.clone(),
			broker: publisher.broker.clone(),
			secret_key: publisher.secret_key.clone(),
			config: publisher.config.clone(),
		})
	}

	pub fn start(&mut self, handler: Box<dyn SubscriptionHandler + Send>) -> Result<(), Error> {
		self.broker.subscribe(
			&self.address,
			&self.secret_key,
			handler,
			self.config.clone(),
		);
		Ok(())
	}

	pub fn stop(&mut self) -> bool {
		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(60))
			.build()
			.unwrap();

		let mut params = HashMap::new();
		params.insert("mapmessage", "nil");
		let response = client
			.post(&format!(
				"https://{}:{}/sender?address={}",
				self.config.mwcmqs_domain(),
				self.config.mwcmqs_port(),
				str::replace(&self.address.stripped(), "@", "%40")
			))
			.form(&params)
			.send();

		let response_status = response.is_ok();
		self.broker.stop();
		return response_status;
	}

	pub fn is_running(&self) -> bool {
		self.broker.is_running()
	}
}

#[derive(Clone)]
struct MWCMQSBroker {
	inner: Arc<Mutex<Option<()>>>,
	config: MQSConfig,
}

impl MWCMQSBroker {
	fn new(config: MQSConfig) -> Result<Self, Error> {
		Ok(Self {
			inner: Arc::new(Mutex::new(None)),
			config: config,
		})
	}

	fn post_slate(
		&self,
		slate: &Slate,
		to: &MWCMQSAddress,
		from: &MWCMQSAddress,
		secret_key: &SecretKey,
	) -> Result<(), Error> {
		if !self.is_running() {
			return Err(ErrorKind::ClosedListener("mwcmqs".to_string()).into());
		}
		let pkey = to.public_key()?;
		let domain = &to.domain;
		let port = to.port;
		let skey = secret_key.clone();

		let to_str = str::replace(
			&format!(
				"{:?}@{}:{}",
				&to.public_key,
				domain,
				port.unwrap_or(DEFAULT_MWCMQS_PORT)
			),
			"\"",
			"",
		);
		let message = EncryptedMessage::new(
			serde_json::to_string(&slate)?,
			&GrinboxAddress::from_str(&to_str)?,
			&pkey,
			&skey,
		)
		.map_err(|_| WsError::new(WsErrorKind::Protocol, "could not encrypt slate!"))?;

		let message_ser = &serde_json::to_string(&message)?;
		let mut challenge = String::new();
		challenge.push_str(&message_ser);
		let signature = sign_challenge(&challenge, secret_key);
		let signature = signature.unwrap().to_hex();

		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(60))
			.build()?;

		let mser: &str = &message_ser;
		let fromstripped = from.stripped();

		let mut params = HashMap::new();
		params.insert("mapmessage", mser);
		params.insert("from", &fromstripped);
		params.insert("signature", &signature);

		let response = client
			.post(&format!(
				"https://{}:{}/sender?address={}",
				self.config.mwcmqs_domain(),
				self.config.mwcmqs_port(),
				&str::replace(&to.stripped(), "@", "%40")
			))
			.form(&params)
			.send();

		if !response.is_ok() {
			return Err(ErrorKind::InvalidRespose("mwcmqs connection error".to_string()).into());
		} else {
			let mut response = response.unwrap();
			let mut resp_str = "".to_string();
			let read_resp = response.read_to_string(&mut resp_str);

			if !read_resp.is_ok() {
				return Err(ErrorKind::InvalidRespose("mwcmqs i/o error".to_string()).into());
			} else {
				let data: Vec<&str> = resp_str.split(" ").collect();
				if data.len() <= 1 {
					return Err(ErrorKind::InvalidRespose("mwcmqs".to_string()).into());
				} else {
					let last_seen = data[1].parse::<i64>();
					if !last_seen.is_ok() {
						return Err(ErrorKind::InvalidRespose("mwcmqs".to_string()).into());
					} else {
						let last_seen = last_seen.unwrap();
						if last_seen > 10000000000 {
							println!("\nWARNING: [{}] has not been connected to mwcmqs recently. This user might not receive the slate.",
                                  to.stripped().bright_green());
						} else if last_seen > 150000 {
							let seconds = last_seen / 1000;
							println!("\nWARNING: [{}] has not been connected to mwcmqs for {} seconds. This user might not receive the slate.",
                                  to.stripped().bright_green(), seconds);
						}
					}
				}
			}
		}

		Ok(())
	}

	fn print_error(&mut self, messages: Vec<&str>, error: &str, code: i16) {
		println!(
			"{}: messages=[{:?}] produced error: {} (code={})",
			"ERROR".bright_red(),
			messages,
			error,
			code
		);
	}

	fn subscribe(
		&mut self,
		address: &MWCMQSAddress,
		secret_key: &SecretKey,
		handler: Box<dyn SubscriptionHandler + Send>,
		config: MQSConfig,
	) -> () {
		let _index = 0;
		let grinbox_address = GrinboxAddress::new(
			crate::crypto::public_key_from_secret_key(&config.get_mwcmqs_secret_key().unwrap())
				.unwrap(),
			Some(config.mwcmqs_domain()),
			Some(config.mwcmqs_port()),
		);

		let nanoid = nanoid::simple();
		let handler = Arc::new(Mutex::new(handler));
		{
			let mut guard = self.inner.lock();
			*guard = Some(());
		}

		let mut resp_str = "".to_string();
		let secret_key = secret_key.clone();
		let cloned_address = address.clone();
		let cloned_inner = self.inner.clone();
		let mut count = 0;
		let mut connected = false;
		let mut isnginxerror = false;
		let mut delcount = 0;
		let mut is_in_warning = false;

		// get time from server
		let mut time_now = "";
		let mut is_error = false;
		let secs = 10;
		let cl = reqwest::Client::builder()
			.timeout(Duration::from_secs(secs))
			.build();
		if cl.is_ok() {
			let client = cl.unwrap();
			let resp_result = client
				.get(&format!(
					"https://{}:{}/timenow?address={}",
					config.mwcmqs_domain(),
					config.mwcmqs_port(),
					str::replace(&cloned_address.stripped(), "@", "%40"),
				))
				.send();

			if !resp_result.is_ok() {
				is_error = true;
			} else {
				let mut resp = resp_result.unwrap();
				let read_resp = resp.read_to_string(&mut resp_str);
				if !read_resp.is_ok() {
					is_error = true;
				} else {
					time_now = &resp_str;
				}
			}
		} else {
			is_error = true;
		}

		let time_now_signature = sign_challenge(&format!("{}", time_now), &secret_key);
		let time_now_signature = str::replace(
			&format!("{:?}", &time_now_signature.unwrap()),
			"Signature(",
			"",
		);
		let time_now_signature = str::replace(&time_now_signature, ")", "");

		let mut url = String::from(&format!(
			"https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}",
			config.mwcmqs_domain(),
			config.mwcmqs_port(),
			str::replace(&cloned_address.stripped(), "@", "%40"),
			"nil".to_string(),
			time_now,
			time_now_signature
		));

		let first_url = String::from(&format!(
			"https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}&first=true",
			config.mwcmqs_domain(),
			config.mwcmqs_port(),
			str::replace(&cloned_address.stripped(), "@", "%40"),
			"nil".to_string(),
			time_now,
			time_now_signature
		));

		if is_error {
			print!(
				"\r{}: Failed to start mwcmqs subscriber. Error connecting to {}:{}\n",
				"ERROR".bright_red(),
				config.mwcmqs_domain(),
				config.mwcmqs_port()
			);
		} else {
			let mut is_error = false;
			let mut loop_count = 0;
			loop {
				loop_count = loop_count + 1;
				if is_error {
					break;
				}
				let mut resp_str = "".to_string();
				count = count + 1;
				let cloned_cloned_address = cloned_address.clone();
				{
					let mut guard = cloned_inner.lock();
					if guard.is_none() {
						break;
					}
					*guard = Some(());
				}

				let is_stopped = cloned_inner.lock().is_none();
				if is_stopped {
					break;
				}

				let secs = if !connected { 2 } else { 120 };
				let cl = reqwest::Client::builder()
					.timeout(Duration::from_secs(secs))
					.build();
				let client = if cl.is_ok() {
					cl.unwrap()
				} else {
					self.print_error([].to_vec(), "couldn't instantiate client", -101);
					is_error = true;
					continue;
				};

				let mut first_response = true;
				let resp_result = if loop_count == 1 {
					client.get(&*first_url).send()
				} else {
					client.get(&*url).send()
				};

				if !resp_result.is_ok() {
					let err_message = format!("{:?}", resp_result);
					let re = Regex::new(TIMEOUT_ERROR_REGEX).unwrap();
					let captures = re.captures(&err_message);
					if captures.is_none() {
						// This was not a timeout. Sleep first.
						if connected {
							is_in_warning = true;
							println!("\n{}: mwcmqs listener [{}] lost connection. Will try to restore in the background. tid=[{}]",
                                 "WARNING".bright_yellow(),
                                 cloned_cloned_address.stripped().bright_green(), nanoid );
						}

						let second = time::Duration::from_millis(5000);
						thread::sleep(second);

						connected = false;
					} else if count == 1 {
						delcount = 0;
						println!(
							"\nmwcmqs listener started for [{}] tid=[{}]",
							cloned_cloned_address.stripped().bright_green(),
							nanoid
						);
						print!("{}", COLORED_PROMPT);
						connected = true;
					} else {
						delcount = 0;
						if !connected {
							if is_in_warning {
								println!(
									"{}: mwcmqs listener [{}] reestablished connection. tid=[{}]",
									"INFO".bright_blue(),
									cloned_cloned_address.stripped().bright_green(),
									nanoid
								);
								is_in_warning = false;
								isnginxerror = false;
							}
						}
						connected = true;
					}
				} else {
					if count == 1 {
						println!(
							"\nmwcmqs listener started for [{}] tid=[{}]",
							cloned_cloned_address.stripped().bright_green(),
							nanoid
						);
						print!("{}", COLORED_PROMPT);
					} else if !connected && !isnginxerror {
						if is_in_warning {
							println!(
								"{}: listener [{}] reestablished connection.",
								"INFO".bright_blue(),
								cloned_cloned_address.stripped().bright_green()
							);
							is_in_warning = false;
							isnginxerror = false;
						}
						connected = true;
					} else if !isnginxerror {
						connected = true;
					}

					let mut resp = resp_result.unwrap();
					let read_resp = resp.read_to_string(&mut resp_str);
					if !read_resp.is_ok() {
						// read error occured. Sleep and try again in 5 seconds
						println!("io error occured while trying to connect to {}. Will sleep for 5 second and will reconnect.",
                                 &format!("https://{}:{}", config.mwcmqs_domain(), config.mwcmqs_port()));
						println!("Error: {:?}", read_resp);
						let second = time::Duration::from_millis(5000);
						thread::sleep(second);
						continue;
					}

					let mut break_out = false;

					let msgvec: Vec<&str> = if resp_str.starts_with("messagelist: ") {
						let mut ret: Vec<&str> = Vec::new();
						let lines: Vec<&str> = resp_str.split("\n").collect();
						for i in 1..lines.len() {
							let params: Vec<&str> = lines[i].split(" ").collect();
							if params.len() >= 2 {
								let index = params[1].find(';');
								if index.is_some() {
									// new format
									let index = index.unwrap();
									let mut last_message_id = &params[1][0..index];
									let start = last_message_id.find(' ');
									if start.is_some() {
										last_message_id = &last_message_id[1 + start.unwrap()..];
									}

									url = String::from(format!(
                                        "https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}",
                                        config.mwcmqs_domain(),
                                        config.mwcmqs_port(),
                                        str::replace(&cloned_address.stripped(), "@", "%40"),
                                        &last_message_id,
                                        time_now,
                                        time_now_signature
                                    ));
									ret.push(&params[1][index + 1..]);
								} else if params[1] == "closenewlogin" {
									let is_stopped = cloned_inner.lock().is_none();
									if !is_stopped {
										print!(
											"\n{}: new login detected. mwcmqs listener will stop!",
											"ERROR".bright_red()
										);
									}
									break; // stop listener
								} else {
									self.print_error([].to_vec(), "message id expected", -103);
									is_error = true;
									continue;
								}
							}
						}
						ret
					} else {
						let index = resp_str.find(';');
						if index.is_some() {
							// new format
							let index = index.unwrap();

							let mut last_message_id = &resp_str[0..index];
							let start = last_message_id.find(' ');
							if start.is_some() {
								last_message_id = &last_message_id[1 + start.unwrap()..];
							}

							url = String::from(format!(
                            "https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}",
                            config.mwcmqs_domain(),
                            config.mwcmqs_port(),
                            str::replace(&cloned_address.stripped(), "@", "%40"),
                            &last_message_id,
                            time_now,
                            time_now_signature
                            ));

							vec![&resp_str[index + 1..]]
						} else {
							if resp_str.find("nginx").is_some() {
								// this is common for nginx to return if the server is down.
								// so we don't print. We also add a small sleep here.
								connected = false;
								if !isnginxerror {
									is_in_warning = true;
									println!("\n{}: mwcmqs listener [{}] lost connection. Will try to restore in the background. tid=[{}]",
                                        "WARNING".bright_yellow(),
                                         cloned_cloned_address.stripped().bright_green(),
                                     nanoid);
								}
								isnginxerror = true;
								let second = time::Duration::from_millis(5000);
								thread::sleep(second);
								continue;
							} else {
								if resp_str == "message: closenewlogin\n" {
									let is_stopped = cloned_inner.lock().is_none();
									if !is_stopped {
										print!(
											"\n{}: new login detected. mwcmqs listener will stop!",
											"ERROR".bright_red()
										);
									}
									break; // stop listener
								} else if resp_str == "message: mapmessage=nil" {
									// our connection message
									continue;
								} else {
									self.print_error([].to_vec(), "message id expected", -102);
									is_error = true;
									continue;
								}
							}
						}
					};

					for itt in 0..msgvec.len() {
						if break_out {
							break;
						}
						if msgvec[itt] == "message: closenewlogin\n"
							|| msgvec[itt] == "closenewlogin"
						{
							let is_stopped = cloned_inner.lock().is_none();
							if !is_stopped {
								print!(
									"\n{}: new login detected. mwcmqs listener will stop!",
									"ERROR".bright_red()
								);
							}
							break_out = true;
							break; // stop listener
						} else if msgvec[itt] == "message: mapmessage=nil\n"
							|| msgvec[itt] == "mapmessage=nil"
							|| msgvec[itt] == "mapmessage=nil\n"
						{
							if first_response {
								delcount = 1;
								first_response = false;
							} else {
								delcount = delcount + 1;
							}
							// this is our exit message. Just ignore.
							continue;
						}
						let split = msgvec[itt].split(" ");
						let vec: Vec<&str> = split.collect();
						let splitx = if vec.len() == 1 {
							vec[0].split("&")
						} else if vec.len() >= 2 {
							vec[1].split("&")
						} else {
							self.print_error(msgvec.clone(), "too many spaced messages", -1);
							is_error = true;
							continue;
						};

						let splitxvec: Vec<&str> = splitx.collect();
						let splitxveclen = splitxvec.len();
						if splitxveclen != 3 {
							if msgvec[itt].find("nginx").is_some() {
								// this is common for nginx to return if the server is down.
								// so we don't print. We also add a small sleep here.
								connected = false;
								if !isnginxerror {
									is_in_warning = true;
									println!("\n{}: mwcmqs listener [{}] lost connection. Will try to restore in the background. tid=[{}]",
                                     "WARNING".bright_yellow(),
                                     cloned_cloned_address.stripped().bright_green(),
                                     nanoid);
								}
								isnginxerror = true;
								let second = time::Duration::from_millis(5000);
								thread::sleep(second);
							} else {
								self.print_error(msgvec.clone(), "splitxveclen != 3", -2);
								is_error = true;
							}
							continue;
						} else if isnginxerror {
							isnginxerror = false;
							connected = true;
						}

						let mut from = "".to_string();
						for i in 0..3 {
							if splitxvec[i].starts_with("from=") {
								let vec: Vec<&str> = splitxvec[i].split("=").collect();
								if vec.len() <= 1 {
									self.print_error(msgvec.clone(), "vec.len <= 1", -3);
									is_error = true;
									continue;
								}
								from = str::replace(
									&vec[1].to_string().trim().to_string(),
									"%40",
									"@",
								);
							}
						}
						let mut signature = "".to_string();
						for i in 0..3 {
							if splitxvec[i].starts_with("signature=") {
								let vec: Vec<&str> = splitxvec[i].split("=").collect();
								if vec.len() <= 1 {
									self.print_error(msgvec.clone(), "vec.len <= 1", -4);
									is_error = true;
									continue;
								}
								signature = vec[1].to_string().trim().to_string();
							}
						}

						for i in 0..3 {
							if splitxvec[i].starts_with("mapmessage=") {
								let split2 = splitxvec[i].split("=");
								let vec2: Vec<&str> = split2.collect();
								if vec2.len() <= 1 {
									self.print_error(msgvec.clone(), "vec2.len <= 1", -5);
									is_error = true;
									continue;
								}
								let r1 = str::replace(vec2[1], "%22", "\"");
								let r2 = str::replace(&r1, "%7B", "{");
								let r3 = str::replace(&r2, "%7D", "}");
								let r4 = str::replace(&r3, "%3A", ":");
								let r5 = str::replace(&r4, "%2C", ",");
								let r5 = r5.trim().to_string();

								if first_response {
									delcount = 1;
									first_response = false;
								} else {
									delcount = delcount + 1;
								}

								let (mut slate, mut tx_proof) = match TxProof::from_response(
									from.clone(),
									r5.clone(),
									"".to_string(),
									signature.clone(),
									&secret_key,
									Some(&grinbox_address),
								) {
									Ok(x) => x,
									Err(err) => {
										println!("{}", err);
										continue;
									}
								};

								let from = MWCMQSAddress::from_str(&from);
								let from = if !from.is_ok() {
									self.print_error(msgvec.clone(), "error parsing from", -12);
									is_error = true;
									continue;
								} else {
									from.unwrap()
								};

								handler.lock().on_slate(
									&from,
									&mut slate,
									Some(&mut tx_proof),
									Some(self.config.clone()),
								);
								break;
							}
						}
					}

					if break_out {
						break;
					}
				}
			}
		}

		if !is_error {
			println!(
				"\nmwcmqs listener [{}] stopped. tid=[{}]",
				address.stripped().bright_green(),
				nanoid
			);
		}
		let mut guard = cloned_inner.lock();
		*guard = None;
	}

	fn stop(&self) {
		let mut guard = self.inner.lock();
		if let Some(ref _sender) = *guard {}
		*guard = None;
	}

	fn is_running(&self) -> bool {
		let guard = self.inner.lock();
		guard.is_some()
	}
}
