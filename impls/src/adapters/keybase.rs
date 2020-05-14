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

// Keybase Wallet Plugin

use super::types::{
	Address, CloseReason, KeybaseAddress, Publisher, Subscriber, SubscriptionHandler,
};
use crate::adapters::SlateSender;
use crate::error::{Error, ErrorKind};
use crate::libwallet::Slate;
use crate::util::Mutex;
use grin_util::RwLock;
use grin_wallet_config::WalletConfig;
use grin_wallet_libwallet::proof::proofaddress::ProvableAddress;
use grinswap::swap::message::Message;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::iter::FromIterator;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

pub const TOPIC_SLATE_NEW: &str = "grin_slate_new";
pub const TOPIC_WALLET_SLATES: &str = "wallet713_grin_slate";
const TOPIC_SLATE_SIGNED: &str = "grin_slate_signed";
const SLEEP_DURATION: Duration = Duration::from_millis(5000);

// Keybase is following MQS design and enforcing a single instance. And different compoments migth manage
// instances separatlly.
// Since instance is single, interface will be global
lazy_static! {
	static ref KEYBASE_BROKER: RwLock<Option<(KeybasePublisher, KeybaseSubscriber)>> =
		RwLock::new(None);
}

/// Init mwc mqs objects for the access.
pub fn init_keybase_access_data(publisher: KeybasePublisher, subscriber: KeybaseSubscriber) {
	KEYBASE_BROKER.write().replace((publisher, subscriber));
}

/// Init mwc mqs objects for the access.
pub fn get_keybase_brocker() -> Option<(KeybasePublisher, KeybaseSubscriber)> {
	KEYBASE_BROKER.read().clone()
}

pub struct KeybaseChannel {
	des_address: String,
	finalize: bool,
}

impl KeybaseChannel {
	pub fn new(des_address: String, finalize: bool) -> Self {
		Self {
			des_address: des_address,
			finalize: finalize,
		}
	}

	fn send_tx_keybase(
		&self,
		slate: &Slate,
		mwcmqs_publisher: KeybasePublisher,
		rx_slate: Receiver<Slate>,
		tx_finalize: Sender<bool>,
	) -> Result<Slate, Error> {
		let des_address = KeybaseAddress::from_str(self.des_address.as_ref()).map_err(|e| {
			ErrorKind::KeybaseGenericError(format!("Invalid destination address, {}", e))
		})?;
		tx_finalize.send(self.finalize).map_err(|e| {
			ErrorKind::KeybaseGenericError(format!("Unable to contact MQS worker, {}", e))
		})?;
		mwcmqs_publisher
			.post_slate(&slate, &des_address)
			.map_err(|e| {
				ErrorKind::KeybaseGenericError(format!(
					"MQS unable to transfer slate {} to the worker, {}",
					slate.id, e
				))
			})?;

		//expect to get slate back.
		let slate_returned = rx_slate
			.recv_timeout(Duration::from_secs(120))
			.map_err(|e| {
				ErrorKind::KeybaseGenericError(format!(
					"MQS unable to process slate {}, {}",
					slate.id, e
				))
			})?;
		return Ok(slate_returned);
	}
}

impl SlateSender for KeybaseChannel {
	fn send_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		if let Some((keybase_publisher, keybase_subscriber)) = get_keybase_brocker() {
			// Creating channels for notification
			let (tx_slate, rx_slate) = channel(); //this chaneel is used for listener thread to send message to other thread
									  //this chaneel is used for listener thread to receive message from other thread
			let (tx_finalize, rx_finalize) = channel();

			keybase_subscriber.set_notification_channels(tx_slate, rx_finalize);
			let res = self.send_tx_keybase(slate, keybase_publisher, rx_slate, tx_finalize);
			keybase_subscriber.reset_notification_channels();
			res
		} else {
			return Err(ErrorKind::KeybaseGenericError(format!(
				"Keybase is not started, not able to send the slate {}",
				slate.id
			))
			.into());
		}
	}
}

#[derive(Clone)]
pub struct KeybasePublisher {
	ttl: Option<String>,
	keybase_binary: Option<String>,
}

impl KeybasePublisher {
	pub fn new(ttl: Option<String>, keybase_binary: Option<String>) -> Result<Self, Error> {
		let _broker = KeybaseBroker::new(keybase_binary.clone())?;
		Ok(Self {
			ttl,
			keybase_binary,
		})
	}
}

#[derive(Clone)]
pub struct KeybaseSubscriber {
	handler: Arc<Mutex<Box<dyn SubscriptionHandler + Send>>>,
	stop_signal: Arc<Mutex<bool>>,
	keybase_binary: Option<String>,
}

impl KeybaseSubscriber {
	pub fn new(
		keybase_binary: Option<String>,
		handler: Box<dyn SubscriptionHandler + Send>,
	) -> Self {
		Self {
			handler: Arc::new(Mutex::new(handler)),
			stop_signal: Arc::new(Mutex::new(true)),
			keybase_binary: keybase_binary,
		}
	}
}

impl Publisher for KeybasePublisher {
	fn post_slate(&self, slate: &Slate, to: &dyn Address) -> Result<(), Error> {
		let keybase_address = KeybaseAddress::from_str(&to.to_string())?;

		// make sure we don't send message with ttl to wallet713 as keybase oneshot does not support exploding lifetimes
		let ttl = match keybase_address.username.as_ref() {
			"wallet713" => &None,
			_ => &self.ttl,
		};

		let topic = match &keybase_address.topic {
			Some(t) => t,
			None => TOPIC_WALLET_SLATES,
		};

		KeybaseBroker::send(
			&slate,
			&to.get_stripped(),
			topic,
			ttl,
			self.keybase_binary.clone(),
		)?;

		Ok(())
	}

	fn encrypt_slate(&self, _slate: &Slate, _to: &dyn Address) -> Result<String, Error> {
		unimplemented!();
	}

	fn decrypt_slate(
		&self,
		_from: String,
		_mapmessage: String,
		_signature: String,
		_source_address: &ProvableAddress,
	) -> Result<String, Error> {
		unimplemented!();
	}

	fn post_take(&self, message: &Message, to: &str) -> Result<(), Error> {
		Ok(())
	}
}

impl Subscriber for KeybaseSubscriber {
	fn start(&mut self) -> Result<(), Error> {
		{
			let mut guard = self.stop_signal.lock();
			*guard = false;
		}

		let mut subscribed = false;
		let mut dropped = false;
		let result: Result<(), Error> = loop {
			if *self.stop_signal.lock() {
				break Ok(());
			};
			let result = KeybaseBroker::get_unread(
				self.keybase_binary.clone(),
				HashSet::from_iter(vec![
					TOPIC_WALLET_SLATES,
					TOPIC_SLATE_NEW,
					TOPIC_SLATE_SIGNED,
				]),
			);
			if let Ok(unread) = result {
				if !subscribed {
					subscribed = true;
					self.handler.lock().on_open();
				}
				if dropped {
					dropped = false;
					self.handler.lock().on_reestablished();
				}
				for (sender, topic, msg) in &unread {
					let reply_topic = match topic.as_ref() {
						TOPIC_SLATE_NEW => TOPIC_SLATE_SIGNED.to_string(),
						_ => TOPIC_WALLET_SLATES.to_string(),
					};
					let mut slate = Slate::deserialize_upgrade(&msg)?;
					let address = KeybaseAddress {
						username: sender.to_string(),
						topic: Some(reply_topic),
					};
					self.handler.lock().on_slate(&address, &mut slate, None);
				}
			} else {
				if !dropped {
					dropped = true;
					if subscribed {
						self.handler.lock().on_dropped();
					} else {
						break Err(ErrorKind::KeybaseNotFound.into());
					}
				}
			}
			std::thread::sleep(SLEEP_DURATION);
		};
		match result {
			Err(e) => self.handler.lock().on_close(CloseReason::Abnormal(e)),
			_ => self.handler.lock().on_close(CloseReason::Normal),
		}
		Ok(())
	}

	fn stop(&mut self) -> bool {
		let mut guard = self.stop_signal.lock();
		*guard = true;
		return true;
	}

	fn is_running(&self) -> bool {
		let guard = self.stop_signal.lock();
		!*guard
	}

	fn set_notification_channels(
		&self,
		slate_send_channel: Sender<Slate>,
		message_receive_channel: Receiver<bool>,
	) {
		self.handler
			.lock()
			.set_notification_channels(slate_send_channel, message_receive_channel);
	}

	fn reset_notification_channels(&self) {
		self.handler.lock().reset_notification_channels();
	}
	fn on_message(&mut self, from: &dyn Address, message: Message, config: &WalletConfig) {}
}

struct KeybaseBroker {}

impl KeybaseBroker {
	pub fn new(keybase_binary: Option<String>) -> Result<Self, Error> {
		// where doesn't handle path verification at all. It expect path and pattern.
		// That is why for this case checking for file existance
		if cfg!(target_os = "windows") && keybase_binary.is_some() {
			if Path::new(&keybase_binary.unwrap()).exists() {
				return Ok(Self {});
			} else {
				return Err(ErrorKind::KeybaseNotFound)?;
			}
		}

		let mut proc = if cfg!(target_os = "windows") {
			Command::new("where")
		} else {
			Command::new("which")
		};

		let status = if keybase_binary.is_some() {
			proc.arg(keybase_binary.unwrap())
				.stdout(Stdio::null())
				.status()
				.map_err(|e| {
					ErrorKind::KeybaseGenericError(format!(
						"Unable to locate keybase binary, {}",
						e
					))
				})?
		} else {
			proc.arg("keybase")
				.stdout(Stdio::null())
				.status()
				.map_err(|e| {
					ErrorKind::KeybaseGenericError(format!(
						"Unable to locate keybase binary, {}",
						e
					))
				})?
		};

		if status.success() {
			Ok(Self {})
		} else {
			Err(ErrorKind::KeybaseNotFound)?
		}
	}

	pub fn api_send(keybase_binary: Option<String>, payload: &str) -> Result<Value, Error> {
		let mut proc = if keybase_binary.is_some() {
			Command::new(keybase_binary.unwrap())
		} else {
			Command::new("keybase")
		};
		proc.args(&["chat", "api", "-m", &payload]);
		let output = proc.output().expect("No output").stdout;
		let response = std::str::from_utf8(&output).map_err(|e| {
			ErrorKind::KeybaseGenericError(format!("Unable to read keybase response, {}", e))
		})?;
		let response: Value = serde_json::from_str(response).map_err(|e| {
			ErrorKind::KeybaseGenericError(format!(
				"Unable to parse as json keybase response {}, {}",
				response, e
			))
		})?;
		Ok(response)
	}

	pub fn read_from_channel(
		channel: &str,
		topic: &str,
		keybase_binary: Option<String>,
	) -> Result<Vec<(String, String, String)>, Error> {
		let payload = json!({
			"method": "read",
			"params": {
				"options": {
					"channel": {
						"name": channel,
						"topic_type": "dev",
						"topic_name": topic
					},
					"unread_only": true,
					"peek": false
				},
			}
		});
		let payload = serde_json::to_string(&payload).map_err(|e| {
			ErrorKind::KeybaseGenericError(format!(
				"Unable convert internal payload to Json, {}",
				e
			))
		})?;
		let response = KeybaseBroker::api_send(keybase_binary, &payload).map_err(|e| {
			ErrorKind::KeybaseGenericError(format!("Failed to send paylod {}, {}", payload, e))
		})?;

		let mut unread: Vec<(String, String, String)> = Vec::new();
		let messages = response["result"]["messages"].as_array();
		if let Some(messages) = messages {
			for msg in messages.iter() {
				if (msg["msg"]["content"]["type"] == "text") && (msg["msg"]["unread"] == true) {
					let message = msg["msg"]["content"]["text"]["body"].as_str().unwrap_or("");
					let sender: &str = msg["msg"]["sender"]["username"].as_str().unwrap_or("");
					if !message.is_empty() && !sender.is_empty() {
						unread.push((sender.to_string(), topic.to_string(), message.to_string()));
					}
				}
			}
		}
		Ok(unread)
	}

	pub fn get_unread(
		keybase_binary: Option<String>,
		topics: HashSet<&str>,
	) -> Result<Vec<(String, String, String)>, Error> {
		let payload = json!({
			"method": "list",
			"params": {
				"options": {
					"topic_type": "dev",
				},
			}
		});
		let payload = serde_json::to_string(&payload).map_err(|e| {
			ErrorKind::KeybaseGenericError(format!(
				"Unable convert internal payload to Json, {}",
				e
			))
		})?;
		let response = KeybaseBroker::api_send(keybase_binary.clone(), &payload).map_err(|e| {
			ErrorKind::KeybaseGenericError(format!("Failed to send paylod {}, {}", payload, e))
		})?;

		let mut channels = HashSet::new();
		let messages = response["result"]["conversations"].as_array();
		if let Some(messages) = messages {
			for msg in messages.iter() {
				let topic = msg["channel"]["topic_name"].as_str().unwrap();
				if (msg["unread"] == true) && topics.contains(topic) {
					let channel = msg["channel"]["name"].as_str().unwrap();
					channels.insert((channel.to_string(), topic));
				}
			}
		}

		let mut unread: Vec<(String, String, String)> = Vec::new();
		for (channel, topic) in channels.iter() {
			let mut messages =
				KeybaseBroker::read_from_channel(channel, topic, keybase_binary.clone())?;
			unread.append(&mut messages);
		}
		Ok(unread)
	}

	pub fn send<T: Serialize>(
		message: &T,
		channel: &str,
		topic: &str,
		ttl: &Option<String>,
		keybase_binary: Option<String>,
	) -> Result<(), Error> {
		let mut payload = json!({
			"method": "send",
			"params": {
				"options": {
					"channel": {
						"name": channel,
						"topic_name": topic,
						"topic_type": "dev"
					},
					"message": {
						"body": serde_json::to_string(&message)
							.map_err(|e| ErrorKind::KeybaseGenericError(format!("Unable to serialize a message, {}", e)))?
					}
				}
			}
		});

		if let Some(ttl) = ttl {
			payload["params"]["options"]["exploding_lifetime"] = json!(ttl);
		}

		let payload = serde_json::to_string(&payload).map_err(|e| {
			ErrorKind::KeybaseGenericError(format!(
				"Unable convert internal payload to Json, {}",
				e
			))
		})?;

		let response = KeybaseBroker::api_send(keybase_binary, &payload).map_err(|e| {
			ErrorKind::KeybaseGenericError(format!("Failed to send paylod {}, {}", payload, e))
		})?;

		match response["result"]["message"].as_str() {
			Some("message sent") => Ok(()),
			Some(s) => Err(ErrorKind::KeybaseMessageSendError(format!(
				"keybase responded with {}",
				s
			)))?,
			_ => Err(ErrorKind::KeybaseMessageSendError(format!(
				"Unexpected keybase respond: {}",
				response
			)))?,
		}
	}
}
