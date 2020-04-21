// Copyright 2020 The MWC Developers
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

use crate::error::{Error, ErrorKind};
use crate::libwallet::proof::crypto;
use crate::libwallet::proof::crypto::Hex;
use grin_wallet_libwallet::proof::message::EncryptedMessage;
use grin_wallet_libwallet::proof::proofaddress::ProvableAddress;
use grin_wallet_libwallet::proof::tx_proof::TxProof;
use grin_wallet_libwallet::Slate;
use grin_wallet_util::grin_util::secp::key::SecretKey;
use regex::Regex;
use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{thread, time};

extern crate nanoid;

pub enum CloseReason {
	Normal,
	Abnormal(Error),
}

pub trait SubscriptionHandler: Send {
	fn on_open(&self);
	fn on_slate(&self, from: &MWCMQSAddress, slate: &mut Slate, proof: Option<&mut TxProof>);
	fn on_close(&self, result: CloseReason);
	fn on_dropped(&self);
	fn on_reestablished(&self);
}

const TIMEOUT_ERROR_REGEX: &str = r"timed out";
const DEFAULT_MWCMQS_DOMAIN: &str = "mqs.mwc.mw";
pub const DEFAULT_MWCMQS_PORT: u16 = 443;

#[derive(Clone)]
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

	/// Extract the address plus additional data
	pub fn from_str(s: &str) -> Result<Self, Error> {
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

	pub fn get_stripped(&self) -> String {
		let mut res = self.address.public_key.clone();
		if self.domain != DEFAULT_MWCMQS_DOMAIN || self.port != DEFAULT_MWCMQS_PORT {
			res.push_str(&format!("@{}", self.domain));
			if self.port != DEFAULT_MWCMQS_PORT {
				res.push_str(&format!(":{}", self.port));
			}
		}
		res
	}

	pub fn to_string(&self) -> String {
		format!("mwcmqs://{}", self.get_stripped())
	}
}

#[derive(Clone)]
pub struct MWCMQPublisher {
	address: MWCMQSAddress,
	broker: MWCMQSBroker,
	secret_key: SecretKey,
}

impl MWCMQPublisher {
	pub fn new(
		address: MWCMQSAddress,
		secret_key: &SecretKey,
		mwcmqs_domain: String,
		mwcmqs_port: u16,
	) -> Result<Self, Error> {
		Ok(Self {
			address,
			broker: MWCMQSBroker::new(mwcmqs_domain, mwcmqs_port),
			secret_key: secret_key.clone(),
		})
	}

	pub fn post_slate(&self, slate: &Slate, to: &MWCMQSAddress) -> Result<(), Error> {
		self.broker
			.post_slate(slate, to, &self.address, &self.secret_key)?;
		Ok(())
	}
}

#[derive(Clone)]
pub struct MWCMQSubscriber {
	address: MWCMQSAddress,
	broker: MWCMQSBroker,
	secret_key: SecretKey,
}

impl MWCMQSubscriber {
	pub fn new(publisher: &MWCMQPublisher) -> Result<Self, Error> {
		Ok(Self {
			address: publisher.address.clone(),
			broker: publisher.broker.clone(),
			secret_key: publisher.secret_key.clone(),
		})
	}

	pub fn start(&mut self, handler: Box<dyn SubscriptionHandler + Send>) -> Result<(), Error> {
		self.broker
			.subscribe(&self.address.address, &self.secret_key, handler);
		Ok(())
	}

	pub fn stop(&mut self) -> bool {
		if let Ok(client) = reqwest::Client::builder()
			.timeout(Duration::from_secs(60))
			.build()
		{
			let mut params = HashMap::new();
			params.insert("mapmessage", "nil");
			let response = client
				.post(&format!(
					"https://{}:{}/sender?address={}",
					self.broker.mwcmqs_domain,
					self.broker.mwcmqs_port,
					str::replace(&self.address.get_stripped(), "@", "%40")
				))
				.form(&params)
				.send();

			let response_status = response.is_ok();
			self.broker.stop();
			response_status
		} else {
			error!("Unable to stop mwcmqs threads");
			false
		}
	}

	pub fn is_running(&self) -> bool {
		self.broker.is_running()
	}
}

#[derive(Clone)]
struct MWCMQSBroker {
	running: Arc<AtomicBool>,
	pub mwcmqs_domain: String,
	pub mwcmqs_port: u16,
}

impl MWCMQSBroker {
	fn new(mwcmqs_domain: String, mwcmqs_port: u16) -> Self {
		Self {
			running: Arc::new(AtomicBool::new(false)),
			mwcmqs_domain,
			mwcmqs_port,
		}
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
		let pkey = to.address.public_key()?;
		let skey = secret_key.clone();

		let message = EncryptedMessage::new(
			serde_json::to_string(&slate).map_err(|e| {
				ErrorKind::MqsGenericError(format!("Unable convert Slate to Json, {}", e))
			})?,
			&to.address,
			&pkey,
			&skey,
		)
		.map_err(|e| ErrorKind::GenericError(format!("Unable encrypt slate, {}", e)))?;

		let message_ser = &serde_json::to_string(&message).map_err(|e| {
			ErrorKind::MqsGenericError(format!("Unable convert Message to Json, {}", e))
		})?;

		let mut challenge = String::new();
		challenge.push_str(&message_ser);
		let signature = crypto::sign_challenge(&challenge, secret_key)?;
		let signature = signature.to_hex();

		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(120))
			.build()
			.map_err(|e| ErrorKind::GenericError(format!("Failed to build a client, {}", e)))?;

		let mser: &str = &message_ser;
		let fromstripped = from.get_stripped();

		let mut params = HashMap::new();
		params.insert("mapmessage", mser);
		params.insert("from", &fromstripped);
		params.insert("signature", &signature);

		let response = client
			.post(&format!(
				"https://{}:{}/sender?address={}",
				self.mwcmqs_domain,
				self.mwcmqs_port,
				&str::replace(&to.get_stripped(), "@", "%40")
			))
			.form(&params)
			.send();

		if !response.is_ok() {
			return Err(ErrorKind::MqsInvalidRespose("mwcmqs connection error".to_string()).into());
		} else {
			let mut response = response.unwrap();
			let mut resp_str = "".to_string();
			let read_resp = response.read_to_string(&mut resp_str);

			if !read_resp.is_ok() {
				return Err(ErrorKind::MqsInvalidRespose("mwcmqs i/o error".to_string()).into());
			} else {
				let data: Vec<&str> = resp_str.split(" ").collect();
				if data.len() <= 1 {
					return Err(ErrorKind::MqsInvalidRespose("mwcmqs".to_string()).into());
				} else {
					let last_seen = data[1].parse::<i64>();
					if !last_seen.is_ok() {
						return Err(ErrorKind::MqsInvalidRespose("mwcmqs".to_string()).into());
					} else {
						let last_seen = last_seen.unwrap();
						if last_seen > 10000000000 {
							println!("\nWARNING: [{}] has not been connected to mwcmqs recently. This user might not receive the slate.",
                                  to.get_stripped());
						} else if last_seen > 150000 {
							let seconds = last_seen / 1000;
							println!("\nWARNING: [{}] has not been connected to mwcmqs for {} seconds. This user might not receive the slate.",
                                  to.get_stripped(), seconds);
						}
					}
				}
			}
		}

		Ok(())
	}

	fn print_error(&mut self, messages: Vec<&str>, error: &str, code: i16) {
		println!(
			"ERROR: messages=[{:?}] produced error: {} (code={})",
			messages, error, code
		);
	}

	fn subscribe(
		&mut self,
		source_address: &ProvableAddress,
		secret_key: &SecretKey,
		handler: Box<dyn SubscriptionHandler + Send>,
	) -> () {
		let address = MWCMQSAddress::new(
			source_address.clone(),
			Some(self.mwcmqs_domain.clone()),
			Some(self.mwcmqs_port),
		);

		let nanoid = nanoid::simple();
		self.running.store(true, Ordering::SeqCst);

		let mut resp_str = "".to_string();
		let secret_key = secret_key.clone();
		let cloned_address = address.clone();
		let cloned_running = self.running.clone();
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
					self.mwcmqs_domain,
					self.mwcmqs_port,
					str::replace(&cloned_address.get_stripped(), "@", "%40"),
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

		let mut time_now_signature = String::new();
		if let Ok(time_now_sign) = crypto::sign_challenge(&format!("{}", time_now), &secret_key) {
			let time_now_sign = str::replace(&format!("{:?}", time_now_sign), "Signature(", "");
			let time_now_sign = str::replace(&time_now_sign, ")", "");
			time_now_signature = time_now_sign;
		}

		if time_now_signature.is_empty() {
			is_error = true;
		}

		let mut url = String::from(&format!(
			"https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}",
			self.mwcmqs_domain,
			self.mwcmqs_port,
			str::replace(&cloned_address.get_stripped(), "@", "%40"),
			"nil".to_string(),
			time_now,
			time_now_signature
		));

		let first_url = String::from(&format!(
			"https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}&first=true",
			self.mwcmqs_domain,
			self.mwcmqs_port,
			str::replace(&cloned_address.get_stripped(), "@", "%40"),
			"nil".to_string(),
			time_now,
			time_now_signature
		));

		if is_error {
			print!(
				"ERROR: Failed to start mwcmqs subscriber. Error connecting to {}:{}",
				self.mwcmqs_domain, self.mwcmqs_port
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

				if !cloned_running.load(Ordering::SeqCst) {
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
							println!("\nWARNING: mwcmqs listener [{}] lost connection. Will try to restore in the background. tid=[{}]",
                                 cloned_cloned_address.get_stripped(), nanoid );
						}

						let second = time::Duration::from_millis(5000);
						thread::sleep(second);

						connected = false;
					} else if count == 1 {
						delcount = 0;
						println!(
							"\nmwcmqs listener started for [{}] tid=[{}]",
							cloned_cloned_address.get_stripped(),
							nanoid
						);
						connected = true;
					} else {
						delcount = 0;
						if !connected {
							if is_in_warning {
								println!(
									"INFO: mwcmqs listener [{}] reestablished connection. tid=[{}]",
									cloned_cloned_address.get_stripped(),
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
							cloned_cloned_address.get_stripped(),
							nanoid
						);
					} else if !connected && !isnginxerror {
						if is_in_warning {
							println!(
								"INFO: listener [{}] reestablished connection.",
								cloned_cloned_address.get_stripped()
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
                                 &format!("https://{}:{}", self.mwcmqs_domain, self.mwcmqs_port));
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
                                        self.mwcmqs_domain,
										self.mwcmqs_port,
                                        str::replace(&cloned_address.get_stripped(), "@", "%40"),
                                        &last_message_id,
                                        time_now,
                                        time_now_signature
                                    ));
									ret.push(&params[1][index + 1..]);
								} else if params[1] == "closenewlogin" {
									if cloned_running.load(Ordering::SeqCst) {
										print!(
											"\nERROR: new login detected. mwcmqs listener will stop!"
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
                            self.mwcmqs_domain,
                            self.mwcmqs_port,
                            str::replace(&cloned_address.get_stripped(), "@", "%40"),
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
									println!("\nWARNING: mwcmqs listener [{}] lost connection. Will try to restore in the background. tid=[{}]",
                                         cloned_cloned_address.get_stripped(),
                                     nanoid);
								}
								isnginxerror = true;
								let second = time::Duration::from_millis(5000);
								thread::sleep(second);
								continue;
							} else {
								if resp_str == "message: closenewlogin\n" {
									if cloned_running.load(Ordering::SeqCst) {
										print!(
											"\nERROR: new login detected. mwcmqs listener will stop!",
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
							if cloned_running.load(Ordering::SeqCst) {
								print!("\nERROR: new login detected. mwcmqs listener will stop!",);
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
									println!("\nWARNING: mwcmqs listener [{}] lost connection. Will try to restore in the background. tid=[{}]",
                                     cloned_cloned_address.get_stripped(),
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

								let from = MWCMQSAddress::from_str(&from);
								let from = if !from.is_ok() {
									self.print_error(msgvec.clone(), "error parsing from", -12);
									is_error = true;
									continue;
								} else {
									from.unwrap()
								};

								let (mut slate, mut tx_proof) = match TxProof::from_response(
									&from.address,
									r5.clone(),
									"".to_string(),
									signature.clone(),
									&secret_key,
									&source_address,
								) {
									Ok(x) => x,
									Err(err) => {
										println!("{}", err);
										continue;
									}
								};

								handler.on_slate(&from, &mut slate, Some(&mut tx_proof));
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
				address.get_stripped(),
				nanoid
			);
		}

		cloned_running.store(false, Ordering::SeqCst);
	}

	fn stop(&self) {
		self.running.store(false, Ordering::SeqCst);
	}

	fn is_running(&self) -> bool {
		self.running.load(Ordering::SeqCst)
	}
}
