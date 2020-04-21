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

/// HTTP Wallet 'plugin' implementation
use crate::client_utils::{Client, ClientError};
use crate::error::{Error, ErrorKind};
use crate::libwallet::slate_versions::{SlateVersion, VersionedSlate};
use crate::libwallet::Slate;
use crate::SlateSender;
use serde::Serialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::MAIN_SEPARATOR;

use crate::tor::config as tor_config;
use crate::tor::process as tor_process;

const TOR_CONFIG_PATH: &'static str = "tor/sender";

#[derive(Clone)]
pub struct HttpSlateSender {
	base_url: String,
	apisecret: Option<String>,
	use_socks: bool,
	socks_proxy_addr: Option<SocketAddr>,
	tor_config_dir: String,
}

impl HttpSlateSender {
	/// Create, return Err if scheme is not "http"
	pub fn new(base_url: &str, apisecret: Option<String>) -> Result<HttpSlateSender, Error> {
		if !base_url.starts_with("http") && !base_url.starts_with("https") {
			Err(ErrorKind::GenericError(format!("Invalid http url: {}", base_url)).into())
		} else {
			Ok(HttpSlateSender {
				base_url: base_url.to_owned(),
				apisecret,
				use_socks: false,
				socks_proxy_addr: None,
				tor_config_dir: String::from(""),
			})
		}
	}

	/// Switch to using socks proxy
	pub fn with_socks_proxy(
		base_url: &str,
		apisecret: Option<String>,
		proxy_addr: &str,
		tor_config_dir: &str,
	) -> Result<HttpSlateSender, Error> {
		let mut ret = Self::new(base_url, apisecret)?;
		ret.use_socks = true;
		let addr = proxy_addr.parse().map_err(|e| {
			ErrorKind::GenericError(format!("Anable to parse address {}, {}", proxy_addr, e))
		})?;
		ret.socks_proxy_addr = Some(SocketAddr::V4(addr));
		ret.tor_config_dir = tor_config_dir.into();
		Ok(ret)
	}

	/// Check version of the listening wallet
	fn check_other_version(&self, url: &str) -> Result<SlateVersion, Error> {
		let req = json!({
			"jsonrpc": "2.0",
			"method": "check_version",
			"id": 1,
			"params": []
		});

		let res_str: String = self.post(url, self.apisecret.clone(), req).map_err(|e| {
			let mut report = format!("Performing version check (is recipient listening?): {}", e);
			let err_string = format!("{}", e);
			if err_string.contains("404") {
				// Report that the other version of the wallet is out of date
				report = format!(
					"Other wallet is incompatible and requires an upgrade. \
					 Please urge the other wallet owner to upgrade and try the transaction again."
				);
			}
			error!("{}", report);
			ErrorKind::ClientCallback(report)
		})?;

		let res: Value = serde_json::from_str(&res_str).map_err(|e| {
			ErrorKind::GenericError(format!("Unable to parse respond {}, {}", res_str, e))
		})?;
		trace!("Response: {}", res);
		if res["error"] != json!(null) {
			let report = format!(
				"Posting transaction slate: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}

		let resp_value = res["result"]["Ok"].clone();
		trace!("resp_value: {}", resp_value.clone());
		let foreign_api_version: u16 =
			serde_json::from_value(resp_value["foreign_api_version"].clone()).map_err(|e| {
				ErrorKind::GenericError(format!(
					"Unable to read respond foreign_api_version value {}, {}",
					res_str, e
				))
			})?;
		let supported_slate_versions: Vec<String> = serde_json::from_value(
			resp_value["supported_slate_versions"].clone(),
		)
		.map_err(|e| {
			ErrorKind::GenericError(format!(
				"Unable to read respond supported_slate_versions value {}, {}",
				res_str, e
			))
		})?;

		// trivial tests for now, but will be expanded later
		if foreign_api_version < 2 {
			let report = format!("Other wallet reports unrecognized API format.");
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}

		if supported_slate_versions.contains(&"V3".to_owned()) {
			return Ok(SlateVersion::V3);
		}
		if supported_slate_versions.contains(&"V2".to_owned()) {
			return Ok(SlateVersion::V2);
		}

		let report = format!("Unable to negotiate slate format with other wallet.");
		error!("{}", report);
		Err(ErrorKind::ClientCallback(report).into())
	}

	fn post<IN>(
		&self,
		url: &str,
		api_secret: Option<String>,
		input: IN,
	) -> Result<String, ClientError>
	where
		IN: Serialize,
	{
		let mut client = Client::new();
		if self.use_socks {
			client.use_socks = true;
			client.socks_proxy_addr = self.socks_proxy_addr.clone();
		}

		let req = client.create_post_request(url, Some("mwc".to_string()), api_secret, &input)?;
		let res = client.send_request(req)?;
		Ok(res)
	}
}

impl SlateSender for HttpSlateSender {
	fn send_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		let trailing = match self.base_url.ends_with('/') {
			true => "",
			false => "/",
		};
		let url_str = format!("{}{}v2/foreign", self.base_url, trailing);

		// set up tor send process if needed
		let mut tor = tor_process::TorProcess::new();
		if self.use_socks {
			let tor_dir = format!(
				"{}{}{}",
				&self.tor_config_dir, MAIN_SEPARATOR, TOR_CONFIG_PATH
			);
			warn!(
				"Starting TOR Process for send at {:?}",
				self.socks_proxy_addr
			);
			tor_config::output_tor_sender_config(
				&tor_dir,
				&self
					.socks_proxy_addr
					.ok_or(ErrorKind::GenericError(
						"Not found socks_proxy_addr value".to_string(),
					))?
					.to_string(),
			)
			.map_err(|e| ErrorKind::TorConfig(format!("Failed to config tor, {}", e).into()))?;
			// Start TOR process
			let tor_cmd = format!("{}/torrc", &tor_dir);
			tor.torrc_path(&tor_cmd)
				.working_dir(&tor_dir)
				.timeout(20)
				.completion_percent(100)
				.launch()
				.map_err(|e| {
					ErrorKind::TorProcess(
						format!("Unable to start tor process {}, {:?}", tor_cmd, e).into(),
					)
				})?;
		}

		let slate_send = match self.check_other_version(&url_str)? {
			SlateVersion::V3 => VersionedSlate::into_version(slate.clone(), SlateVersion::V3),
			SlateVersion::V2 => {
				let mut slate = slate.clone();
				if let Some(_) = slate.payment_proof {
					return Err(ErrorKind::ClientCallback("Payment proof requested, but other wallet does not support payment proofs. Please urge other user to upgrade, or re-send tx without a payment proof".into()).into());
				}
				if let Some(_) = slate.ttl_cutoff_height {
					warn!("Slate TTL value will be ignored and removed by other wallet, as other wallet does not support this feature. Please urge other user to upgrade");
				}
				slate.version_info.version = 2;
				slate.version_info.orig_version = 2;
				VersionedSlate::into_version(slate, SlateVersion::V2)
			}
		};
		// Note: not using easy-jsonrpc as don't want the dependencies in this crate
		let req = json!({
			"jsonrpc": "2.0",
			"method": "receive_tx",
			"id": 1,
			"params": [
						slate_send,
						null,
						null
					]
		});
		trace!("Sending receive_tx request: {}", req);

		let res_str: String = self
			.post(&url_str, self.apisecret.clone(), req)
			.map_err(|e| {
				let report = format!("Posting transaction slate (is recipient listening?): {}", e);
				error!("{}", report);
				ErrorKind::ClientCallback(report)
			})?;

		let res: Value = serde_json::from_str(&res_str).map_err(|e| {
			ErrorKind::GenericError(format!("Unable to parse respond {}, {}", res_str, e))
		})?;
		trace!("Response: {}", res);
		if res["error"] != json!(null) {
			let report = format!(
				"Posting transaction slate: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}

		let slate_value = res["result"]["Ok"].clone();
		trace!("slate_value: {}", slate_value);
		let slate =
			Slate::deserialize_upgrade(&serde_json::to_string(&slate_value).map_err(|e| {
				ErrorKind::GenericError(format!("Unable to build slate from values, {}", e))
			})?)
			.map_err(|e| {
				ErrorKind::GenericError(format!("Unable to build slate from json, {}", e))
			})?;

		Ok(slate)
	}
}
