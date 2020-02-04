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

//! Controller for wallet.. instantiates and handles listeners (or single-run
//! invocations) as needed.

use crate::api::{self, ApiServer, BasicAuthMiddleware, ResponseFuture, Router, TLSConfig};
use crate::keychain::Keychain;
use crate::libwallet::{
	address, ErrorKind, NodeClient, NodeVersionInfo, Slate, WalletInst, WalletLCProvider,
	GRIN_BLOCK_HEADER_VERSION,
};
use failure::Error;
use grin_wallet_common::mwcmq::CloseReason;
use grin_wallet_common::tx_proof::TxProof;
use grin_wallet_common::COLORED_PROMPT;
use grin_wallet_config::TorConfig;
use grin_wallet_util::grin_core::core;
use std::thread;

use crate::util::secp::key::SecretKey;
use crate::util::{from_hex, static_secp_instance, to_base64, Mutex};
use colored::Colorize;
use failure::ResultExt;
use futures::future::{err, ok};
use futures::{Future, Stream};
use grin_wallet_common::mwcmq::MQSConfig;
use grin_wallet_common::mwcmq::MWCMQPublisher;
use grin_wallet_common::mwcmq::MWCMQSubscriber;
use grin_wallet_common::mwcmq::Publisher;
use grin_wallet_common::mwcmq::SubscriptionHandler;
use grin_wallet_common::types::Address;
use grin_wallet_common::types::AddressBook;
use grin_wallet_common::types::AddressType;
use grin_wallet_common::types::GrinboxAddress;
use grin_wallet_common::wallet::Wallet;
use grin_wallet_libwallet::wallet_lock;
use hyper::header::HeaderValue;
use hyper::{Body, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::impls::tor::config as tor_config;
use crate::impls::tor::process as tor_process;

use crate::apiwallet::{
	EncryptedRequest, EncryptedResponse, EncryptionErrorResponse, Foreign,
	ForeignCheckMiddlewareFn, ForeignRpc, Owner, OwnerRpc, OwnerRpcS,
};
use easy_jsonrpc_mw;
use easy_jsonrpc_mw::{Handler, MaybeReply};

lazy_static! {
	pub static ref MWC_OWNER_BASIC_REALM: HeaderValue =
		HeaderValue::from_str("Basic realm=MWC-OwnerAPI").unwrap();
}

fn check_middleware(
	name: ForeignCheckMiddlewareFn,
	node_version_info: Option<NodeVersionInfo>,
	slate: Option<&Slate>,
) -> Result<(), crate::libwallet::Error> {
	match name {
		// allow coinbases to be built regardless
		ForeignCheckMiddlewareFn::BuildCoinbase => Ok(()),
		_ => {
			let mut bhv = 2;
			if let Some(n) = node_version_info {
				bhv = n.block_header_version;
			}
			if let Some(s) = slate {
				if bhv > 3 && s.version_info.block_header_version < GRIN_BLOCK_HEADER_VERSION {
					Err(ErrorKind::Compatibility(
						"Incoming Slate is not compatible with this wallet. \
						 Please upgrade the node or use a different one."
							.into(),
					))?;
				}
			}
			Ok(())
		}
	}
}

/// initiate the tor listener
fn init_tor_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
) -> Result<tor_process::TorProcess, crate::libwallet::Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let mut process = tor_process::TorProcess::new();
	let mask = keychain_mask.lock();
	// eventually want to read a list of service config keys
	let mut w_lock = wallet.lock();
	let lc = w_lock.lc_provider()?;
	let w_inst = lc.wallet_inst()?;
	let k = w_inst.keychain((&mask).as_ref())?;
	let parent_key_id = w_inst.parent_key_id();
	let tor_dir = format!("{}/tor/listener", lc.get_top_level_directory()?);
	let sec_key = address::address_from_derivation_path(&k, &parent_key_id, 0)
		.map_err(|e| ErrorKind::TorConfig(format!("{:?}", e).into()))?;
	let onion_address = tor_config::onion_address_from_seckey(&sec_key)
		.map_err(|e| ErrorKind::TorConfig(format!("{:?}", e).into()))?;
	warn!(
		"Starting TOR Hidden Service for API listener at address {}, binding to {}",
		onion_address, addr
	);
	tor_config::output_tor_listener_config(&tor_dir, addr, &vec![sec_key])
		.map_err(|e| ErrorKind::TorConfig(format!("{:?}", e).into()))?;
	// Start TOR process
	process
		.torrc_path(&format!("{}/torrc", tor_dir))
		.working_dir(&tor_dir)
		.timeout(20)
		.completion_percent(100)
		.launch()
		.map_err(|e| ErrorKind::TorProcess(format!("{:?}", e).into()))?;
	Ok(process)
}

/// Instantiate wallet Owner API for a single-use (command line) call
/// Return a function containing a loaded API context to call
pub fn owner_single_use<L, F, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	f: F,
) -> Result<(), crate::libwallet::Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	F: FnOnce(&mut Owner<L, C, K>, Option<&SecretKey>) -> Result<(), crate::libwallet::Error>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	f(&mut Owner::new(wallet), keychain_mask)?;
	Ok(())
}

/// Instantiate wallet Foreign API for a single-use (command line) call
/// Return a function containing a loaded API context to call
pub fn foreign_single_use<'a, L, F, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<SecretKey>,
	f: F,
) -> Result<(), crate::libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	F: FnOnce(&mut Foreign<'a, L, C, K>) -> Result<(), crate::libwallet::Error>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	f(&mut Foreign::new(
		wallet,
		keychain_mask,
		Some(check_middleware),
	))?;
	Ok(())
}

struct Controller {
	name: String,
	wallet: Arc<Mutex<Wallet>>,
	address_book: Arc<Mutex<AddressBook>>,
	publisher: Box<dyn Publisher + Send>,
}

impl Controller {
	pub fn new(
		name: &str,
		wallet: Arc<Mutex<Wallet>>,
		address_book: Arc<Mutex<AddressBook>>,
		publisher: Box<dyn Publisher + Send>,
	) -> Result<Self, crate::libwallet::Error> {
		Ok(Self {
			name: name.to_string(),
			wallet,
			address_book,
			publisher,
		})
	}

	fn process_incoming_slate(
		&self,
		address: Option<String>,
		slate: &mut Slate,
		tx_proof: Option<&mut TxProof>,
		config: Option<MQSConfig>,
		dest_acct_name: Option<&str>,
	) -> Result<bool, Error> {
		if slate.num_participants > slate.participant_data.len() {
			//TODO: this needs to be changed to properly figure out if this slate is an invoice or a send
			if slate.tx.inputs().len() == 0 {
				let w = self.wallet.lock();
				let w = w.get_wallet_instance().unwrap();

				let mut w_lock = w.lock().unwrap();
				let lc = w_lock.lc_provider().unwrap();
				let w_inst = lc.wallet_inst().unwrap();
			/*
											self.wallet
												.lock()
												.process_receiver_initiated_slate(slate, address.clone())?;
			*/
			} else {
				/*
												let mut w = self.wallet.lock();
												w.process_sender_initiated_slate(address, slate, None, None, dest_acct_name)?;
				*/
			}
			Ok(false)
		} else {
			// Try both to finalize
			let w = self.wallet.lock();
			/*
									match w.finalize_slate(slate, tx_proof) {
										Err(_) => w.finalize_invoice_slate(slate)?,
										Ok(_) => (),
									}
			*/
			Ok(true)
		}
	}
}

impl SubscriptionHandler for Controller {
	fn on_open(&self) {
		println!("listener started for [{}]", self.name.bright_green());
		print!("{}", COLORED_PROMPT);
	}

	fn on_slate(
		&self,
		from: &dyn Address,
		slate: &mut Slate,
		tx_proof: Option<&mut TxProof>,
		config: Option<MQSConfig>,
	) {
		let mut display_from = from.stripped();
		if let Ok(contact) = self
			.address_book
			.lock()
			.get_contact_by_address(&from.to_string())
		{
			display_from = contact.get_name().to_string();
		}

		if slate.num_participants > slate.participant_data.len() {
			let message = &slate.participant_data[0].message;
			if message.is_some() {
				println!(
					"slate [{}] received from [{}] for [{}] MWCs. Message: [\"{}\"]",
					slate.id.to_string().bright_green(),
					display_from.bright_green(),
					core::amount_to_hr_string(slate.amount, false).bright_green(),
					message.clone().unwrap().bright_green()
				);
			} else {
				println!(
					"slate [{}] received from [{}] for [{}] MWCs.",
					slate.id.to_string().bright_green(),
					display_from.bright_green(),
					core::amount_to_hr_string(slate.amount, false).bright_green()
				);
			}
		} else {
			println!(
				"slate [{}] received back from [{}] for [{}] MWCs",
				slate.id.to_string().bright_green(),
				display_from.bright_green(),
				core::amount_to_hr_string(slate.amount, false).bright_green()
			);
		};

		if from.address_type() == AddressType::Grinbox {
			GrinboxAddress::from_str(&from.to_string()).expect("invalid mwcmq address");
		}

		let account = {
			// lock must be very local
			let w = self.wallet.lock();
			w.active_account.clone()
		};

		let result = self
			.process_incoming_slate(
				Some(from.to_string()),
				slate,
				tx_proof,
				config,
				Some(&account),
			)
			.and_then(|is_finalized| {
				if !is_finalized {
					self.publisher
						.post_slate(slate, from)
						.map_err(|e| {
							println!("{}: {}", "ERROR".bright_red(), e);
							e
						})
						.expect("failed posting slate!");
					println!(
						"slate [{}] sent back to [{}] successfully",
						slate.id.to_string().bright_green(),
						display_from.bright_green()
					);
				} else {
					println!(
						"slate [{}] finalized successfully",
						slate.id.to_string().bright_green()
					);
				}
				Ok(())
			});

		match result {
			Ok(()) => {}
			Err(e) => println!("{}", e),
		}
	}

	fn on_close(&self, reason: CloseReason) {
		match reason {
			CloseReason::Normal => println!("listener [{}] stopped", self.name.bright_green()),
			CloseReason::Abnormal(_) => println!(
				"{}: listener [{}] stopped unexpectedly",
				"ERROR".bright_red(),
				self.name.bright_green()
			),
		}
	}

	fn on_dropped(&self) {
		println!("{}: listener [{}] lost connection. it will keep trying to restore connection in the background.", "WARNING".bright_yellow(), self.name.bright_green())
	}

	fn on_reestablished(&self) {
		println!(
			"{}: listener [{}] reestablished connection.",
			"INFO".bright_blue(),
			self.name.bright_green()
		)
	}
}

/// Start the mqs listener
fn start_mwcmqs_listener<L, C, K>(
	config: &MQSConfig,
	wallet: Arc<Mutex<Wallet>>,
	address_book: Arc<Mutex<AddressBook>>,
) -> Result<(MWCMQPublisher, MWCMQSubscriber), Error> {
	// make sure wallet is not locked, if it is try to unlock with no passphrase
	{
		let mut wallet = wallet.lock();
		if wallet.is_locked() {
			wallet.unlock(
				config,
				"default",
				grin_wallet_util::grin_util::ZeroingString::from(""),
			)?;
		}
	}

	println!("starting mwcmqs listener...");

	let mwcmqs_address = config.get_mwcmqs_address().unwrap();
	let mwcmqs_secret_key = config.get_mwcmqs_secret_key().unwrap();

	let mwcmqs_publisher = MWCMQPublisher::new(&mwcmqs_address, &mwcmqs_secret_key, config)?;

	let mwcmqs_subscriber = MWCMQSubscriber::new(&mwcmqs_publisher)?;

	let cloned_publisher = mwcmqs_publisher.clone();
	let mut cloned_subscriber = mwcmqs_subscriber.clone();

	let _ = thread::Builder::new()
		.name("mwcmqs-broker".to_string())
		.spawn(move || {
			let controller = Controller::new(
				&mwcmqs_address.stripped(),
				wallet.clone(),
				address_book.clone(),
				Box::new(cloned_publisher),
			)
			.expect("could not start mwcmqs controller!");
			cloned_subscriber
				.start(Box::new(controller))
				.expect("something went wrong!");
		})?;

	Ok((mwcmqs_publisher, mwcmqs_subscriber))
}

/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
/// Note keychain mask is only provided here in case the foreign listener is also being used
/// in the same wallet instance
pub fn owner_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
	api_secret: Option<String>,
	tls_config: Option<TLSConfig>,
	owner_api_include_foreign: Option<bool>,
	owner_api_include_mqs_listener: Option<bool>,
	tor_config: Option<TorConfig>,
) -> Result<(), crate::libwallet::Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let mut router = Router::new();
	if api_secret.is_some() {
		let api_basic_auth =
			"Basic ".to_string() + &to_base64(&("mwc:".to_string() + &api_secret.unwrap()));
		let basic_auth_middleware = Arc::new(BasicAuthMiddleware::new(
			api_basic_auth,
			&MWC_OWNER_BASIC_REALM,
			Some("/v2/foreign".into()),
		));
		router.add_middleware(basic_auth_middleware);
	}
	let mut running_mqs = false;
	if owner_api_include_mqs_listener.unwrap_or(false) {
		running_mqs = true;
	}

	let mut running_foreign = false;
	if owner_api_include_foreign.unwrap_or(false) {
		running_foreign = true;
	}

	let api_handler_v2 = OwnerAPIHandlerV2::new(wallet.clone());
	let api_handler_v3 = OwnerAPIHandlerV3::new(
		wallet.clone(),
		keychain_mask.clone(),
		tor_config,
		running_foreign,
	);

	router
		.add_route("/v2/owner", Arc::new(api_handler_v2))
		.map_err(|_| ErrorKind::GenericError("Router failed to add route".to_string()))?;

	router
		.add_route("/v3/owner", Arc::new(api_handler_v3))
		.map_err(|_| ErrorKind::GenericError("Router failed to add route".to_string()))?;

	// If so configured, add the foreign API to the same port
	if running_foreign {
		warn!("Starting HTTP Foreign API on Owner server at {}.", addr);
		let foreign_api_handler_v2 = ForeignAPIHandlerV2::new(wallet, keychain_mask);
		router
			.add_route("/v2/foreign", Arc::new(foreign_api_handler_v2))
			.map_err(|_| ErrorKind::GenericError("Router failed to add route".to_string()))?;
	}

	// If so configured, run mqs listener
	if running_mqs {
		warn!("Starting MWCMQS Listener");
	}

	let mut apis = ApiServer::new();
	warn!("Starting HTTP Owner API server at {}.", addr);
	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	let api_thread =
		apis.start(socket_addr, router, tls_config)
			.context(ErrorKind::GenericError(
				"API thread failed to start".to_string(),
			))?;
	warn!("HTTP Owner listener started.");
	api_thread
		.join()
		.map_err(|e| ErrorKind::GenericError(format!("API thread panicked :{:?}", e)).into())
}

/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
pub fn foreign_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
	tls_config: Option<TLSConfig>,
	use_tor: bool,
) -> Result<(), crate::libwallet::Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	// need to keep in scope while the main listener is running
	let _tor_process = match use_tor {
		true => match init_tor_listener(wallet.clone(), keychain_mask.clone(), addr) {
			Ok(tp) => Some(tp),
			Err(e) => {
				warn!("Unable to start TOR listener; Check that TOR executable is installed and on your path");
				warn!("Tor Error: {}", e);
				warn!("Listener will be available via HTTP only");
				None
			}
		},
		false => None,
	};

	let api_handler_v2 = ForeignAPIHandlerV2::new(wallet, keychain_mask);
	let mut router = Router::new();

	router
		.add_route("/v2/foreign", Arc::new(api_handler_v2))
		.map_err(|_| ErrorKind::GenericError("Router failed to add route".to_string()))?;

	let mut apis = ApiServer::new();
	warn!("Starting HTTP Foreign listener API server at {}.", addr);
	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	let api_thread =
		apis.start(socket_addr, router, tls_config)
			.context(ErrorKind::GenericError(
				"API thread failed to start".to_string(),
			))?;

	warn!("HTTP Foreign listener started.");

	api_thread
		.join()
		.map_err(|e| ErrorKind::GenericError(format!("API thread panicked :{:?}", e)).into())
}

type WalletResponseFuture =
	Box<dyn Future<Item = Response<Body>, Error = crate::libwallet::Error> + Send>;

/// V2 API Handler/Wrapper for owner functions
pub struct OwnerAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Wallet instance
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
}

impl<L, C, K> OwnerAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Create a new owner API handler for GET methods
	pub fn new(
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	) -> OwnerAPIHandlerV2<L, C, K> {
		OwnerAPIHandlerV2 { wallet }
	}

	fn call_api(
		&self,
		req: Request<Body>,
		api: Owner<L, C, K>,
	) -> Box<dyn Future<Item = serde_json::Value, Error = crate::libwallet::Error> + Send> {
		Box::new(parse_body(req).and_then(move |val: serde_json::Value| {
			let owner_api = &api as &dyn OwnerRpc;
			match owner_api.handle_request(val) {
				MaybeReply::Reply(r) => ok(r),
				MaybeReply::DontReply => {
					// Since it's http, we need to return something. We return [] because jsonrpc
					// clients will parse it as an empty batch response.
					ok(serde_json::json!([]))
				}
			}
		}))
	}

	fn handle_post_request(&self, req: Request<Body>) -> WalletResponseFuture {
		let api = Owner::new(self.wallet.clone());
		Box::new(
			self.call_api(req, api)
				.and_then(|resp| ok(json_response_pretty(&resp))),
		)
	}
}

impl<L, C, K> api::Handler for OwnerAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Body>) -> ResponseFuture {
		Box::new(
			self.handle_post_request(req)
				.and_then(|r| ok(r))
				.or_else(|e| {
					error!("Request Error: {:?}", e);
					ok(create_error_response(e))
				}),
		)
	}

	fn options(&self, _req: Request<Body>) -> ResponseFuture {
		Box::new(ok(create_ok_response("{}")))
	}
}

/// V3 API Handler/Wrapper for owner functions, which include a secure
/// mode + lifecycle functions
pub struct OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Wallet instance
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,

	/// Handle to Owner API
	owner_api: Arc<Owner<L, C, K>>,

	/// ECDH shared key
	pub shared_key: Arc<Mutex<Option<SecretKey>>>,

	/// Keychain mask (to change if also running the foreign API)
	pub keychain_mask: Arc<Mutex<Option<SecretKey>>>,

	/// Whether we're running the foreign API on the same port, and therefore
	/// have to store the mask in-process
	pub running_foreign: bool,
}

pub struct OwnerV3Helpers;

impl OwnerV3Helpers {
	/// Checks whether a request is to init the secure API
	pub fn is_init_secure_api(val: &serde_json::Value) -> bool {
		if let Some(m) = val["method"].as_str() {
			match m {
				"init_secure_api" => true,
				_ => false,
			}
		} else {
			false
		}
	}

	/// Checks whether a request is to open the wallet
	pub fn is_open_wallet(val: &serde_json::Value) -> bool {
		if let Some(m) = val["method"].as_str() {
			match m {
				"open_wallet" => true,
				_ => false,
			}
		} else {
			false
		}
	}

	/// Checks whether a request is an encrypted request
	pub fn is_encrypted_request(val: &serde_json::Value) -> bool {
		if let Some(m) = val["method"].as_str() {
			match m {
				"encrypted_request_v3" => true,
				_ => false,
			}
		} else {
			false
		}
	}

	/// whether encryption is enabled
	pub fn encryption_enabled(key: Arc<Mutex<Option<SecretKey>>>) -> bool {
		let share_key_ref = key.lock();
		share_key_ref.is_some()
	}

	/// If incoming is an encrypted request, check there is a shared key,
	/// Otherwise return an error value
	pub fn check_encryption_started(
		key: Arc<Mutex<Option<SecretKey>>>,
	) -> Result<(), serde_json::Value> {
		match OwnerV3Helpers::encryption_enabled(key) {
			true => Ok(()),
			false => Err(EncryptionErrorResponse::new(
				1,
				-32001,
				"Encryption must be enabled. Please call 'init_secure_api` first",
			)
			.as_json_value()),
		}
	}

	/// Update the statically held owner API shared key
	pub fn update_owner_api_shared_key(
		key: Arc<Mutex<Option<SecretKey>>>,
		val: &serde_json::Value,
		new_key: Option<SecretKey>,
	) {
		if let Some(_) = val["result"]["Ok"].as_str() {
			let mut share_key_ref = key.lock();
			*share_key_ref = new_key;
		}
	}

	/// Update the shared mask, in case of foreign API being run
	pub fn update_mask(mask: Arc<Mutex<Option<SecretKey>>>, val: &serde_json::Value) {
		if let Some(key) = val["result"]["Ok"].as_str() {
			let key_bytes = match from_hex(key.to_owned()) {
				Ok(k) => k,
				Err(_) => return,
			};
			let secp_inst = static_secp_instance();
			let secp = secp_inst.lock();
			let sk = match SecretKey::from_slice(&secp, &key_bytes) {
				Ok(s) => s,
				Err(_) => return,
			};

			let mut shared_mask_ref = mask.lock();
			*shared_mask_ref = Some(sk);
		}
	}

	/// Decrypt an encrypted request
	pub fn decrypt_request(
		key: Arc<Mutex<Option<SecretKey>>>,
		req: &serde_json::Value,
	) -> Result<(u32, serde_json::Value), serde_json::Value> {
		let share_key_ref = key.lock();
		let shared_key = share_key_ref.as_ref().unwrap();
		let enc_req: EncryptedRequest = serde_json::from_value(req.clone()).map_err(|e| {
			EncryptionErrorResponse::new(
				1,
				-32002,
				&format!("Encrypted request format error: {}", e),
			)
			.as_json_value()
		})?;
		let id = enc_req.id;
		let res = enc_req.decrypt(&shared_key).map_err(|e| {
			EncryptionErrorResponse::new(1, -32002, &format!("Decryption error: {}", e.kind()))
				.as_json_value()
		})?;
		Ok((id, res))
	}

	/// Encrypt a response
	pub fn encrypt_response(
		key: Arc<Mutex<Option<SecretKey>>>,
		id: u32,
		res: &serde_json::Value,
	) -> Result<serde_json::Value, serde_json::Value> {
		let share_key_ref = key.lock();
		let shared_key = share_key_ref.as_ref().unwrap();
		let enc_res = EncryptedResponse::from_json(id, res, &shared_key).map_err(|e| {
			EncryptionErrorResponse::new(1, -32003, &format!("EncryptionError: {}", e.kind()))
				.as_json_value()
		})?;
		let res = enc_res.as_json_value().map_err(|e| {
			EncryptionErrorResponse::new(
				1,
				-32002,
				&format!("Encrypted response format error: {}", e),
			)
			.as_json_value()
		})?;
		Ok(res)
	}

	/// convert an internal error (if exists) as proper JSON-RPC
	pub fn check_error_response(val: &serde_json::Value) -> (bool, serde_json::Value) {
		// check for string first. This ensures that error messages
		// that are just strings aren't given weird formatting
		let err_string = if val["result"]["Err"].is_object() {
			let mut retval;
			let hashed: Result<HashMap<String, String>, serde_json::Error> =
				serde_json::from_value(val["result"]["Err"].clone());
			retval = match hashed {
				Err(e) => {
					debug!("Can't cast value to Hashmap<String> {}", e);
					None
				}
				Ok(h) => {
					let mut r = "".to_owned();
					for (k, v) in h.iter() {
						r = format!("{}: {}", k, v);
					}
					Some(r)
				}
			};
			// Otherwise, see if error message is a map that needs
			// to be stringified (and accept weird formatting)
			if retval.is_none() {
				let hashed: Result<HashMap<String, serde_json::Value>, serde_json::Error> =
					serde_json::from_value(val["result"]["Err"].clone());
				retval = match hashed {
					Err(e) => {
						debug!("Can't cast value to Hashmap<Value> {}", e);
						None
					}
					Ok(h) => {
						let mut r = "".to_owned();
						for (k, v) in h.iter() {
							r = format!("{}: {}", k, v);
						}
						Some(r)
					}
				}
			}
			retval
		} else if val["result"]["Err"].is_string() {
			let parsed = serde_json::from_value::<String>(val["result"]["Err"].clone());
			match parsed {
				Ok(p) => Some(p),
				Err(_) => None,
			}
		} else {
			None
		};
		match err_string {
			Some(s) => {
				return (
					true,
					serde_json::json!({
						"jsonrpc": "2.0",
						"id": val["id"],
						"error": {
							"message": s,
							"code": -32099
						}
					}),
				)
			}
			None => (false, val.clone()),
		}
	}
}

impl<L, C, K> OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Create a new owner API handler for GET methods
	pub fn new(
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		tor_config: Option<TorConfig>,
		running_foreign: bool,
	) -> OwnerAPIHandlerV3<L, C, K> {
		let owner_api = Owner::new(wallet.clone());
		owner_api.set_tor_config(tor_config);
		let owner_api = Arc::new(owner_api);
		OwnerAPIHandlerV3 {
			wallet,
			owner_api,
			shared_key: Arc::new(Mutex::new(None)),
			keychain_mask: keychain_mask,
			running_foreign,
		}
	}

	/*
	//Here is a wrapper to call future from that.
	// Issue that we can't call future form future
	Box::new(parse_body(req).and_then(move |val: serde_json::Value| {
			let handler = move || -> serde_json::Value {
				......
			};
			crate::executor::RunHandlerInThread::new(handler)
		}))

	*/

	fn call_api(
		&self,
		req: Request<Body>,
		api: Arc<Owner<L, C, K>>,
	) -> Box<dyn Future<Item = serde_json::Value, Error = crate::libwallet::Error> + Send> {
		let key = self.shared_key.clone();
		let mask = self.keychain_mask.clone();
		let running_foreign = self.running_foreign;
		Box::new(parse_body(req).and_then(move |val: serde_json::Value| {
			let handler = move || -> serde_json::Value {
				let mut val = val;
				let owner_api_s = &*api as &dyn OwnerRpcS;
				let mut is_init_secure_api = OwnerV3Helpers::is_init_secure_api(&val);
				let mut was_encrypted = false;
				let mut encrypted_req_id = 0;
				if !is_init_secure_api {
					if let Err(v) = OwnerV3Helpers::check_encryption_started(key.clone()) {
						return v;
					}
					let res = OwnerV3Helpers::decrypt_request(key.clone(), &val);
					match res {
						Err(e) => return e,
						Ok(v) => {
							encrypted_req_id = v.0;
							val = v.1;
						}
					}
					was_encrypted = true;
				}
				// check again, in case it was an encrypted call to init_secure_api
				is_init_secure_api = OwnerV3Helpers::is_init_secure_api(&val);
				// also need to intercept open/close wallet requests
				let is_open_wallet = OwnerV3Helpers::is_open_wallet(&val);
				match owner_api_s.handle_request(val) {
					MaybeReply::Reply(mut r) => {
						let (_was_error, unencrypted_intercept) =
							OwnerV3Helpers::check_error_response(&r.clone());
						if is_open_wallet && running_foreign {
							OwnerV3Helpers::update_mask(mask, &r.clone());
						}
						if was_encrypted {
							let res = OwnerV3Helpers::encrypt_response(
								key.clone(),
								encrypted_req_id,
								&unencrypted_intercept,
							);
							r = match res {
								Ok(v) => v,
								Err(v) => return v, // Note, grin does return error as 'ok' Json. mwc just following the design
							}
						}
						// intercept init_secure_api response (after encryption,
						// in case it was an encrypted call to 'init_api_secure')
						if is_init_secure_api {
							OwnerV3Helpers::update_owner_api_shared_key(
								key.clone(),
								&unencrypted_intercept,
								api.shared_key.lock().clone(),
							);
						}
						r
					}
					MaybeReply::DontReply => {
						// Since it's http, we need to return something. We return [] because jsonrpc
						// clients will parse it as an empty batch response.
						serde_json::json!([])
					}
				}
			};
			crate::executor::RunHandlerInThread::new(handler)
		}))
	}

	fn handle_post_request(&self, req: Request<Body>) -> WalletResponseFuture {
		Box::new(
			self.call_api(req, self.owner_api.clone())
				.and_then(|resp| ok(json_response_pretty(&resp))),
		)
	}
}

impl<L, C, K> api::Handler for OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Body>) -> ResponseFuture {
		Box::new(
			self.handle_post_request(req)
				.and_then(|r| ok(r))
				.or_else(|e| {
					error!("Request Error: {:?}", e);
					ok(create_error_response(e))
				}),
		)
	}

	fn options(&self, _req: Request<Body>) -> ResponseFuture {
		Box::new(ok(create_ok_response("{}")))
	}
}
/// V2 API Handler/Wrapper for foreign functions
pub struct ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Wallet instance
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	/// Keychain mask
	pub keychain_mask: Arc<Mutex<Option<SecretKey>>>,
}

impl<L, C, K> ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Create a new foreign API handler for GET methods
	pub fn new(
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	) -> ForeignAPIHandlerV2<L, C, K> {
		ForeignAPIHandlerV2 {
			wallet,
			keychain_mask,
		}
	}

	/*
	   //Here is a wrapper to call future from that.
	   // Issue that we can't call future form future
	   Box::new(parse_body(req).and_then(move |val: serde_json::Value| {
			   let handler = move || -> serde_json::Value {
				   ......
			   };
			   crate::executor::RunHandlerInThread::new(handler)
		   }))
	*/

	fn call_api(
		&self,
		req: Request<Body>,
		api: Foreign<'static, L, C, K>,
	) -> Box<dyn Future<Item = serde_json::Value, Error = crate::libwallet::Error> + Send> {
		Box::new(parse_body(req).and_then(move |val: serde_json::Value| {
			let handler = move || -> serde_json::Value {
				let foreign_api = &api as &dyn ForeignRpc;
				match foreign_api.handle_request(val) {
					MaybeReply::Reply(r) => r,
					MaybeReply::DontReply => {
						// Since it's http, we need to return something. We return [] because jsonrpc
						// clients will parse it as an empty batch response.
						serde_json::json!([])
					}
				}
			};
			crate::executor::RunHandlerInThread::new(handler)
		}))
	}

	fn handle_post_request(&self, req: Request<Body>) -> WalletResponseFuture {
		let mask = self.keychain_mask.lock();
		let api = Foreign::new(self.wallet.clone(), mask.clone(), Some(check_middleware));
		Box::new(
			self.call_api(req, api)
				.and_then(|resp| ok(json_response_pretty(&resp))),
		)
	}
}

impl<L, C, K> api::Handler for ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Body>) -> ResponseFuture {
		Box::new(
			self.handle_post_request(req)
				.and_then(|r| ok(r))
				.or_else(|e| {
					error!("Request Error: {:?}", e);
					ok(create_error_response(e))
				}),
		)
	}

	fn options(&self, _req: Request<Body>) -> ResponseFuture {
		Box::new(ok(create_ok_response("{}")))
	}
}

// Utility to serialize a struct into JSON and produce a sensible Response
// out of it.
fn _json_response<T>(s: &T) -> Response<Body>
where
	T: Serialize,
{
	match serde_json::to_string(s) {
		Ok(json) => response(StatusCode::OK, json),
		Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, ""),
	}
}

// pretty-printed version of above
fn json_response_pretty<T>(s: &T) -> Response<Body>
where
	T: Serialize,
{
	match serde_json::to_string_pretty(s) {
		Ok(json) => response(StatusCode::OK, json),
		Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, ""),
	}
}

fn create_error_response(e: crate::libwallet::Error) -> Response<Body> {
	Response::builder()
		.status(StatusCode::INTERNAL_SERVER_ERROR)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.body(format!("{}", e).into())
		.unwrap()
}

fn create_ok_response(json: &str) -> Response<Body> {
	Response::builder()
		.status(StatusCode::OK)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.header(hyper::header::CONTENT_TYPE, "application/json")
		.body(json.to_string().into())
		.unwrap()
}

/// Build a new hyper Response with the status code and body provided.
///
/// Whenever the status code is `StatusCode::OK` the text parameter should be
/// valid JSON as the content type header will be set to `application/json'
fn response<T: Into<Body>>(status: StatusCode, text: T) -> Response<Body> {
	let mut builder = &mut Response::builder();

	builder = builder
		.status(status)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		);

	if status == StatusCode::OK {
		builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
	}

	builder.body(text.into()).unwrap()
}

fn parse_body<T>(
	req: Request<Body>,
) -> Box<dyn Future<Item = T, Error = crate::libwallet::Error> + Send>
where
	for<'de> T: Deserialize<'de> + Send + 'static,
{
	Box::new(
		req.into_body()
			.concat2()
			.map_err(|_| ErrorKind::GenericError("Failed to read request".to_owned()).into())
			.and_then(|body| match serde_json::from_reader(&body.to_vec()[..]) {
				Ok(obj) => ok(obj),
				Err(e) => {
					err(ErrorKind::GenericError(format!("Invalid request body: {}", e)).into())
				}
			}),
	)
}
