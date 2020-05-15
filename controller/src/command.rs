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

//! Grin wallet command-line function implementations

use crate::api::TLSConfig;
use crate::apiwallet::Owner;
use crate::config::{MQSConfig, TorConfig, WalletConfig, WALLET_CONFIG_FILE_NAME};
use crate::core::{core, global};
use crate::error::{Error, ErrorKind};
use crate::impls::{
	create_sender, KeybaseAllChannels, MwcMqsChannel, SlateGetter as _, SlateReceiver as _,
};
use crate::impls::{PathToSlate, SlatePutter};
use crate::keychain;
use crate::libwallet::{
	InitTxArgs, IssueInvoiceTxArgs, NodeClient, PaymentProof, WalletLCProvider,
};
use crate::util::secp::key::SecretKey;
use crate::util::{Mutex, ZeroingString};
use crate::{controller, display};
use grin_wallet_libwallet::TxLogEntry;
use grin_wallet_util::OnionV3Address;
use serde_json as json;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

/// Arguments common to all wallet commands
#[derive(Clone)]
pub struct GlobalArgs {
	pub account: String,
	pub api_secret: Option<String>,
	pub node_api_secret: Option<String>,
	pub show_spent: bool,
	pub chain_type: global::ChainTypes,
	pub password: Option<ZeroingString>,
	pub tls_conf: Option<TLSConfig>,
}

/// Arguments for init command
pub struct InitArgs {
	/// BIP39 recovery phrase length
	pub list_length: usize,
	pub password: ZeroingString,
	pub config: WalletConfig,
	pub recovery_phrase: Option<ZeroingString>,
	pub restore: bool,
}

pub fn init<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	g_args: &GlobalArgs,
	args: InitArgs,
	wallet_data_dir: Option<&str>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut w_lock = owner_api.wallet_inst.lock();
	let p = w_lock.lc_provider()?;
	p.create_config(
		&g_args.chain_type,
		WALLET_CONFIG_FILE_NAME,
		None,
		None,
		None,
		None,
	)?;
	p.create_wallet(
		None,
		args.recovery_phrase,
		args.list_length,
		args.password.clone(),
		false,
		wallet_data_dir.clone(),
	)?;

	let m = p.get_mnemonic(None, args.password, wallet_data_dir)?;
	grin_wallet_impls::lifecycle::show_recovery_phrase(m);
	Ok(())
}

/// Argument for recover
pub struct RecoverArgs {
	pub passphrase: ZeroingString,
}

pub fn recover<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	args: RecoverArgs,
	wallet_data_dir: Option<&str>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut w_lock = owner_api.wallet_inst.lock();
	let p = w_lock.lc_provider()?;
	let m = p.get_mnemonic(None, args.passphrase, wallet_data_dir)?;
	grin_wallet_impls::lifecycle::show_recovery_phrase(m);
	Ok(())
}

/// Arguments for listen command
pub struct ListenArgs {
	pub method: String,
}

pub fn listen<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	config: &WalletConfig,
	tor_config: &TorConfig,
	mqs_config: &MQSConfig,
	args: &ListenArgs,
	g_args: &GlobalArgs,
	cli_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	match args.method.as_str() {
		"http" => {
			let wallet_inst = owner_api.wallet_inst.clone();
			let config = config.clone();
			let tor_config = tor_config.clone();
			let g_args = g_args.clone();
			let api_thread = thread::Builder::new()
				.name("wallet-http-listener".to_string())
				.spawn(move || {
					let res = controller::foreign_listener(
						wallet_inst,
						keychain_mask,
						&config.api_listen_addr(),
						g_args.tls_conf.clone(),
						tor_config.use_tor_listener,
					);
					if let Err(e) = res {
						error!("Error starting http listener: {}", e);
					}
				});
			if let Ok(t) = api_thread {
				if !cli_mode {
					let r = t.join();
					if let Err(_) = r {
						error!("Error starting http listener");
						return Err(ErrorKind::ListenerError.into());
					}
				}
			}
		}
		"keybase" => {
			KeybaseAllChannels::new()?
				.listen(
					config.clone(),
					g_args.password.clone().unwrap(),
					&g_args.account,
					g_args.node_api_secret.clone(),
				)
				.map_err(|e| {
					error!("Unable to start keybase listener, {}", e);
					Error::from(ErrorKind::ListenerError)
				})?;
		}
		"mwcmqs" => {
			let wallet_inst = owner_api.wallet_inst.clone();
			let _ = controller::init_start_mwcmqs_listener(
				config.clone(),
				wallet_inst,
				mqs_config.clone(),
				keychain_mask,
				true,
			)
			.map_err(|e| {
				error!("Unable to start mwcmqs listener, {}", e);
				Error::from(ErrorKind::ListenerError)
			})?;
		}
		method => {
			return Err(
				ErrorKind::ArgumentError(format!("No listener for method '{}'", method)).into(),
			);
		}
	};
	Ok(())
}

pub fn owner_api<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<SecretKey>,
	config: &WalletConfig,
	tor_config: &TorConfig,
	mqs_config: &MQSConfig,
	g_args: &GlobalArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	// keychain mask needs to be a sinlge instance, in case the foreign API is
	// also being run at the same time
	let km = Arc::new(Mutex::new(keychain_mask));

	// Starting MQS first
	if config.owner_api_include_mqs_listener.unwrap_or(false) {
		let _ = controller::init_start_mwcmqs_listener(
			config.clone(),
			owner_api.wallet_inst.clone(),
			mqs_config.clone(),
			km.clone(),
			false,
		)?;
	}

	// Now Owner API
	controller::owner_listener(
		owner_api.wallet_inst.clone(),
		km,
		config.owner_api_listen_addr().as_str(),
		g_args.api_secret.clone(),
		g_args.tls_conf.clone(),
		config.owner_api_include_foreign.clone(),
		Some(tor_config.clone()),
	)
	.map_err(|e| ErrorKind::LibWallet(format!("Unable to start Listener, {}", e)))?;
	Ok(())
}

/// Arguments for account command
pub struct AccountArgs {
	pub create: Option<String>,
}

pub fn account<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: AccountArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	if args.create.is_none() {
		let res = controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let acct_mappings = api.accounts(m)?;
			// give logging thread a moment to catch up
			thread::sleep(Duration::from_millis(200));
			display::accounts(acct_mappings);
			Ok(())
		});
		if let Err(e) = res {
			let err_str = format!("Error listing accounts: {}", e);
			error!("{}", err_str);
			return Err(ErrorKind::LibWallet(err_str).into());
		}
	} else {
		let label = args.create.unwrap();
		let res = controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			api.create_account_path(m, &label)?;
			thread::sleep(Duration::from_millis(200));
			info!("Account: '{}' Created!", label);
			Ok(())
		});
		if let Err(e) = res {
			thread::sleep(Duration::from_millis(200));
			let err_str = format!("Error creating account '{}': {}", label, e);
			error!("{}", err_str);
			return Err(ErrorKind::LibWallet(err_str).into());
		}
	}
	Ok(())
}

/// Arguments for the send command
pub struct SendArgs {
	pub amount: u64,
	pub message: Option<String>,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub estimate_selection_strategies: bool,
	pub method: String,
	pub dest: String,
	pub apisecret: Option<String>,
	pub change_outputs: usize,
	pub fluff: bool,
	pub max_outputs: usize,
	pub target_slate_version: Option<u16>,
	pub payment_proof_address: Option<OnionV3Address>,
	pub ttl_blocks: Option<u64>,
	pub exclude_change_outputs: bool,
	pub minimum_confirmations_change_outputs: u64,
}

pub fn send<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	config: &WalletConfig,
	keychain_mask: Option<&SecretKey>,
	tor_config: Option<TorConfig>,
	mqs_config: Option<MQSConfig>,
	args: SendArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let wallet_inst = owner_api.wallet_inst.clone();
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		if args.estimate_selection_strategies {
			let mut strategies: Vec<(&str, u64, u64)> = Vec::new();
			for strategy in vec!["smallest", "all"] {
				let init_args = InitTxArgs {
					src_acct_name: None,
					amount: args.amount,
					minimum_confirmations: args.minimum_confirmations,
					max_outputs: args.max_outputs as u32,
					num_change_outputs: args.change_outputs as u32,
					selection_strategy_is_use_all: strategy == "all",
					estimate_only: Some(true),
					exclude_change_outputs: Some(args.exclude_change_outputs),
					minimum_confirmations_change_outputs: args.minimum_confirmations_change_outputs,
					..Default::default()
				};
				let slate = api.init_send_tx(m, init_args, None, 1)?;
				strategies.push((strategy, slate.amount, slate.fee));
			}
			display::estimate(args.amount, strategies, dark_scheme);
		} else {
			let init_args = InitTxArgs {
				src_acct_name: None,
				amount: args.amount,
				minimum_confirmations: args.minimum_confirmations,
				max_outputs: args.max_outputs as u32,
				num_change_outputs: args.change_outputs as u32,
				selection_strategy_is_use_all: args.selection_strategy == "all",
				message: args.message.clone(),
				target_slate_version: args.target_slate_version,
				payment_proof_recipient_address: args.payment_proof_address.clone(),
				ttl_blocks: args.ttl_blocks,
				send_args: None,
				exclude_change_outputs: Some(args.exclude_change_outputs),
				minimum_confirmations_change_outputs: args.minimum_confirmations_change_outputs,
				..Default::default()
			};
			let result = api.init_send_tx(m, init_args, None, 1);
			let mut slate = match result {
				Ok(s) => {
					info!(
						"Tx created: {} mwc to {} (strategy '{}')",
						core::amount_to_hr_string(args.amount, false),
						args.dest,
						args.selection_strategy,
					);
					s
				}
				Err(e) => {
					info!("Tx not created: {}", e);
					return Err(ErrorKind::LibWallet(format!(
						"Unable to create send slate , {}",
						e
					))
					.into());
				}
			};

			//if it is mwcmqs, start listner first.
			match args.method.as_str() {
				"mwcmqs" => {
					//check to see if mqs_config is there, if not, return error
					let mqs_config_unwrapped;
					match mqs_config {
						Some(s) => {
							mqs_config_unwrapped = s;
						}
						None => {
							return Err(ErrorKind::MQSConfig(format!("NO MQS config!")).into());
						}
					}

					let km = match keychain_mask.as_ref() {
						None => None,
						Some(&m) => Some(m.to_owned()),
					};
					//start the listener finalize tx
					let _ = controller::init_start_mwcmqs_listener(
						config.clone(),
						wallet_inst.clone(),
						mqs_config_unwrapped,
						Arc::new(Mutex::new(km)),
						false,
					)?;
					thread::sleep(Duration::from_millis(2000));
				}
				_ => {}
			}

			match args.method.as_str() {
				"file" => {
					PathToSlate((&args.dest).into())
						.put_tx(&slate)
						.map_err(|e| {
							ErrorKind::IO(format!(
								"Unable to store the file at {}, {}",
								args.dest, e
							))
						})?;
					api.tx_lock_outputs(m, &slate, Some(String::from("file")), 0)?;
					return Ok(());
				}
				"self" => {
					api.tx_lock_outputs(m, &slate, Some(String::from("self")), 0)?;
					let km = match keychain_mask.as_ref() {
						None => None,
						Some(&m) => Some(m.to_owned()),
					};
					controller::foreign_single_use(wallet_inst, km, |api| {
						slate = api.receive_tx(
							&slate,
							Some(String::from("self")),
							Some(&args.dest),
							None,
						)?;
						Ok(())
					})?;
				}

				method => {
					let sender = create_sender(
						method,
						&args.dest,
						&args.apisecret,
						tor_config,
						Some(MwcMqsChannel::new(args.dest.clone(), true)),
					)?;
					slate = sender.send_tx(&slate)?;
				}
			}

			//for http and keybase, slate needs to be finalized and posted
			//for mwcmqs, slate has already been finalized in the listener thread, here only needs to be posted.
			//right now mwcmqs tx_proof is done in listener thread in finalizing step.
			match args.method.as_str() {
				"http" | "keybase" => {
					api.tx_lock_outputs(m, &slate, Some(args.dest.clone()), 0)?; //this step needs to be done before finalizing the slate
				}

				_ => {}
			}

			match args.method.as_str() {
				"mwcmqs" => {}

				_ => {
					api.verify_slate_messages(m, &slate).map_err(|e| {
						error!("Error validating participant messages: {}", e);
						e
					})?;
					slate = api.finalize_tx(m, &slate)?;
				}
			}

			let result = api.post_tx(m, &slate.tx, args.fluff);
			match result {
				Ok(_) => {
					info!("Tx sent ok",);
					return Ok(());
				}
				Err(e) => {
					error!("Tx sent fail: {}", e);
					return Err(ErrorKind::LibWallet(format!("Unable to post slate, {}", e)).into());
				}
			}
		}
		Ok(())
	})?;
	Ok(())
}

/// Receive command argument
pub struct ReceiveArgs {
	pub input: String,
	pub message: Option<String>,
}

pub fn receive<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: ReceiveArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut slate = PathToSlate((&args.input).into()).get_tx()?;
	let km = match keychain_mask.as_ref() {
		None => None,
		Some(&m) => Some(m.to_owned()),
	};
	controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
		if let Err(e) = api.verify_slate_messages(&slate) {
			error!("Error validating participant messages: {}", e);
			return Err(
				ErrorKind::LibWallet(format!("Unable to validate slate messages, {}", e)).into(),
			);
		}
		slate = api.receive_tx(
			&slate,
			Some(String::from("file")),
			Some(&g_args.account),
			args.message.clone(),
		)?;
		Ok(())
	})?;
	PathToSlate(format!("{}.response", args.input).into()).put_tx(&slate)?;
	info!(
		"Response file {}.response generated, and can be sent back to the transaction originator.",
		args.input
	);
	Ok(())
}

/// Finalize command args
pub struct FinalizeArgs {
	pub input: String,
	pub fluff: bool,
	pub nopost: bool,
	pub dest: Option<String>,
}

pub fn finalize<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: FinalizeArgs,
	is_invoice: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut slate = PathToSlate((&args.input).into()).get_tx()?;

	// Note!!! grin wallet was able to detect if it is invoice by using 'different' participant Ids (issuer use 1, fouset 0)
	//    Unfortunatelly it is breaks mwc713 backward compatibility (issuer Participant Id 0, fouset 1)
	//    We choose backward compatibility as more impotant, that is why we need 'is_invoice' flag to compensate that.

	if is_invoice {
		let km = match keychain_mask.as_ref() {
			None => None,
			Some(&m) => Some(m.to_owned()),
		};
		controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
			if let Err(e) = api.verify_slate_messages(&slate) {
				error!("Error validating participant messages: {}", e);
				return Err(ErrorKind::LibWallet(format!(
					"Unable to validate slate messages, {}",
					e
				))
				.into());
			}
			slate = api.finalize_invoice_tx(&mut slate)?;
			Ok(())
		})?;
	} else {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			if let Err(e) = api.verify_slate_messages(m, &slate) {
				error!("Error validating participant messages: {}", e);
				return Err(ErrorKind::LibWallet(format!(
					"Unable to validate slate messages, {}",
					e
				))
				.into());
			}
			slate = api.finalize_tx(m, &mut slate)?;
			Ok(())
		})?;
	}

	if !args.nopost {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let result = api.post_tx(m, &slate.tx, args.fluff);
			match result {
				Ok(_) => {
					info!(
						"Transaction sent successfully, check the wallet again for confirmation."
					);
					Ok(())
				}
				Err(e) => {
					error!("Tx not sent: {}", e);
					return Err(ErrorKind::LibWallet(format!("Unable to post slate, {}", e)).into());
				}
			}
		})?;
	}

	if args.dest.is_some() {
		PathToSlate((&args.dest.unwrap()).into()).put_tx(&slate)?;
	}

	Ok(())
}

/// Issue Invoice Args
pub struct IssueInvoiceArgs {
	/// output file
	pub dest: String,
	/// issue invoice tx args
	pub issue_args: IssueInvoiceTxArgs,
}

pub fn issue_invoice_tx<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: IssueInvoiceArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let slate = api.issue_invoice_tx(m, args.issue_args)?;
		PathToSlate((&args.dest).into()).put_tx(&slate)?;
		Ok(())
	})?;
	Ok(())
}

/// Arguments for the process_invoice command
pub struct ProcessInvoiceArgs {
	pub message: Option<String>,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub method: String,
	pub dest: String,
	pub max_outputs: usize,
	pub input: String,
	pub estimate_selection_strategies: bool,
	pub ttl_blocks: Option<u64>,
}

/// Process invoice
pub fn process_invoice<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	tor_config: Option<TorConfig>,
	args: ProcessInvoiceArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let slate = PathToSlate((&args.input).into()).get_tx()?;
	let wallet_inst = owner_api.wallet_inst.clone();
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		if args.estimate_selection_strategies {
			let mut strategies: Vec<(&str, u64, u64)> = Vec::new();
			for strategy in vec!["smallest", "all"] {
				let init_args = InitTxArgs {
					src_acct_name: None,
					amount: slate.amount,
					minimum_confirmations: args.minimum_confirmations,
					max_outputs: args.max_outputs as u32,
					num_change_outputs: 1u32,
					selection_strategy_is_use_all: strategy == "all",
					estimate_only: Some(true),
					..Default::default()
				};
				let slate = api.init_send_tx(m, init_args, None, 1)?;
				strategies.push((strategy, slate.amount, slate.fee));
			}
			display::estimate(slate.amount, strategies, dark_scheme);
		} else {
			let init_args = InitTxArgs {
				src_acct_name: None,
				amount: 0,
				minimum_confirmations: args.minimum_confirmations,
				max_outputs: args.max_outputs as u32,
				num_change_outputs: 1u32,
				selection_strategy_is_use_all: args.selection_strategy == "all",
				message: args.message.clone(),
				ttl_blocks: args.ttl_blocks,
				send_args: None,
				..Default::default()
			};
			if let Err(e) = api.verify_slate_messages(m, &slate) {
				error!("Error validating participant messages: {}", e);
				return Err(ErrorKind::LibWallet(format!(
					"Unable to validate slate messages, {}",
					e
				))
				.into());
			}
			let result = api.process_invoice_tx(m, &slate, init_args);
			let mut slate = match result {
				Ok(s) => {
					info!(
						"Invoice processed: {} mwc to {} (strategy '{}')",
						core::amount_to_hr_string(slate.amount, false),
						args.dest,
						args.selection_strategy,
					);
					s
				}
				Err(e) => {
					info!("Tx not created: {}", e);
					return Err(
						ErrorKind::LibWallet(format!("Unable to process invoice, {}", e)).into(),
					);
				}
			};

			match args.method.as_str() {
				"file" => {
					let slate_putter = PathToSlate((&args.dest).into());
					slate_putter.put_tx(&slate)?;
					api.tx_lock_outputs(m, &slate, Some(String::from("file")), 1)?;
				}
				"self" => {
					api.tx_lock_outputs(m, &slate, Some(String::from("self")), 1)?;
					let km = match keychain_mask.as_ref() {
						None => None,
						Some(&m) => Some(m.to_owned()),
					};
					controller::foreign_single_use(wallet_inst, km, |api| {
						slate = api.finalize_invoice_tx(&slate)?;
						Ok(())
					})?;
				}
				method => {
					let sender = create_sender(method, &args.dest, &None, tor_config, None)?;
					slate = sender.send_tx(&slate)?;
					api.tx_lock_outputs(m, &slate, Some(args.dest.clone()), 1)?;
				}
			}
		}
		Ok(())
	})?;
	Ok(())
}
/// Info command args
pub struct InfoArgs {
	pub minimum_confirmations: u64,
}

pub fn info<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: InfoArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let updater_running = owner_api.updater_running.load(Ordering::Relaxed);
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let (validated, wallet_info) =
			api.retrieve_summary_info(m, true, args.minimum_confirmations)?;
		display::info(
			&g_args.account,
			&wallet_info,
			validated || updater_running,
			dark_scheme,
		);
		Ok(())
	})?;
	Ok(())
}

pub fn outputs<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let updater_running = owner_api.updater_running.load(Ordering::Relaxed);
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let res = api.node_height(m)?;
		let (validated, outputs) = api.retrieve_outputs(m, g_args.show_spent, true, None)?;
		display::outputs(
			&g_args.account,
			res.height,
			validated || updater_running,
			outputs,
			dark_scheme,
		)?;
		Ok(())
	})?;
	Ok(())
}

/// Txs command args
pub struct TxsArgs {
	pub id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
}

pub fn txs<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: TxsArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let updater_running = owner_api.updater_running.load(Ordering::Relaxed);
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let res = api.node_height(m)?;
		let (validated, txs) = api.retrieve_txs(m, true, args.id, args.tx_slate_id)?;
		let include_status = !args.id.is_some() && !args.tx_slate_id.is_some();
		display::txs(
			&g_args.account,
			res.height,
			validated || updater_running,
			&txs,
			include_status,
			dark_scheme,
			true, // mwc-wallet alwways show the full info because it is advanced tool
			|tx: &TxLogEntry| tx.payment_proof.is_some(), // it is how mwc-wallet address proofs feature
		)?;

		// if given a particular transaction id or uuid, also get and display associated
		// inputs/outputs and messages
		let id = if args.id.is_some() {
			args.id
		} else if args.tx_slate_id.is_some() {
			if let Some(tx) = txs.iter().find(|t| t.tx_slate_id == args.tx_slate_id) {
				Some(tx.id)
			} else {
				println!("Could not find a transaction matching given txid.\n");
				None
			}
		} else {
			None
		};

		if id.is_some() {
			let (_, outputs) = api.retrieve_outputs(m, true, false, id)?;
			display::outputs(
				&g_args.account,
				res.height,
				validated || updater_running,
				outputs,
				dark_scheme,
			)?;
			// should only be one here, but just in case
			for tx in txs {
				display::tx_messages(&tx, dark_scheme)?;
				display::payment_proof(&tx)?;
			}
		}

		Ok(())
	})?;
	Ok(())
}

/// Post
pub struct PostArgs {
	pub input: String,
	pub fluff: bool,
}

pub fn post<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: PostArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let slate = PathToSlate((&args.input).into()).get_tx()?;

	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		api.post_tx(m, &slate.tx, args.fluff)?;
		info!("Posted transaction");
		return Ok(());
	})?;
	Ok(())
}

/// Submit
pub struct SubmitArgs {
	pub input: String,
	pub fluff: bool,
}

pub fn submit<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: SubmitArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let stored_tx = api.load_stored_tx(&args.input)?;
		api.post_tx(m, &stored_tx, args.fluff)?;
		info!("Reposted transaction in file: {}", args.input);
		return Ok(());
	})?;
	Ok(())
}

/// Repost
pub struct RepostArgs {
	pub id: u32,
	pub dump_file: Option<String>,
	pub fluff: bool,
}

pub fn repost<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: RepostArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let (_, txs) = api.retrieve_txs(m, true, Some(args.id), None)?;
		let stored_tx = api.get_stored_tx(m, &txs[0])?;
		if stored_tx.is_none() {
			error!(
				"Transaction with id {} does not have transaction data. Not reposting.",
				args.id
			);
			return Ok(());
		}
		match args.dump_file {
			None => {
				if txs[0].confirmed {
					error!(
						"Transaction with id {} is confirmed. Not reposting.",
						args.id
					);
					return Ok(());
				}
				api.post_tx(m, &stored_tx.unwrap(), args.fluff)?;
				info!("Reposted transaction at {}", args.id);
				return Ok(());
			}
			Some(f) => {
				let mut tx_file = File::create(f.clone()).map_err(|e| {
					ErrorKind::IO(format!("Unable to create tx dump file {}, {}", f, e))
				})?;
				let tx_as_str = json::to_string(&stored_tx).map_err(|e| {
					ErrorKind::GenericError(format!("Unable convert Tx to Json, {}", e))
				})?;
				tx_file.write_all(tx_as_str.as_bytes()).map_err(|e| {
					ErrorKind::IO(format!("Unable to save tx to the file {}, {}", f, e))
				})?;
				tx_file.sync_all().map_err(|e| {
					ErrorKind::IO(format!("Unable to save tx to the file {}, {}", f, e))
				})?;
				info!("Dumped transaction data for tx {} to {}", args.id, f);
				return Ok(());
			}
		}
	})?;
	Ok(())
}

/// Cancel
pub struct CancelArgs {
	pub tx_id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
	pub tx_id_string: String,
}

pub fn cancel<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: CancelArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result = api.cancel_tx(m, args.tx_id, args.tx_slate_id);
		match result {
			Ok(_) => {
				info!("Transaction {} Cancelled", args.tx_id_string);
				Ok(())
			}
			Err(e) => {
				error!("TX Cancellation failed: {}", e);
				Err(ErrorKind::LibWallet(format!(
					"Unable to cancel Transaction {}, {}",
					args.tx_id_string, e
				))
				.into())
			}
		}
	})?;
	Ok(())
}

/// wallet check
pub struct CheckArgs {
	pub delete_unconfirmed: bool,
	pub start_height: Option<u64>,
	pub backwards_from_tip: Option<u64>,
}

pub fn scan<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: CheckArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let tip_height = api.node_height(m)?.height;
		let start_height = match args.backwards_from_tip {
			Some(b) => tip_height.saturating_sub(b),
			None => match args.start_height {
				Some(s) => s,
				None => 1,
			},
		};
		warn!("Starting output scan from height {} ...", start_height);
		let result = api.scan(m, Some(start_height), args.delete_unconfirmed);
		match result {
			Ok(_) => {
				warn!("Wallet check complete",);
				Ok(())
			}
			Err(e) => {
				error!("Wallet check failed: {}", e);
				error!("Backtrace: {}", e.backtrace().unwrap());
				Err(ErrorKind::LibWallet(format!("Wallet check failed, {}", e)).into())
			}
		}
	})?;
	Ok(())
}

/// Payment Proof Address
pub fn address<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	g_args: &GlobalArgs,
	keychain_mask: Option<&SecretKey>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		// Just address at derivation index 0 for now
		let pub_key = api.get_public_proof_address(m, 0)?;
		let addr = OnionV3Address::from_bytes(pub_key.to_bytes());
		println!();
		println!("Address for account - {}", g_args.account);
		println!("-------------------------------------");
		println!("{}", addr);
		println!();
		Ok(())
	})?;
	Ok(())
}

/// Proof Export Args
pub struct ProofExportArgs {
	pub output_file: String,
	pub id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
}

pub fn proof_export<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ProofExportArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result = api.retrieve_payment_proof(m, true, args.id, args.tx_slate_id);
		match result {
			Ok(p) => {
				// actually export proof
				let mut proof_file = File::create(args.output_file.clone()).map_err(|e| {
					ErrorKind::GenericError(format!(
						"Unable to create file {}, {}",
						args.output_file, e
					))
				})?;
				proof_file
					.write_all(json::to_string_pretty(&p).unwrap().as_bytes())
					.map_err(|e| {
						ErrorKind::GenericError(format!(
							"Unable to save the proof file {}, {}",
							args.output_file, e
						))
					})?;
				proof_file.sync_all().map_err(|e| {
					ErrorKind::GenericError(format!(
						"Unable to save file {}, {}",
						args.output_file, e
					))
				})?;
				warn!("Payment proof exported to {}", args.output_file);
				Ok(())
			}
			Err(e) => {
				error!("Proof export failed: {}", e);
				return Err(ErrorKind::GenericError(format!(
					"Unable to retrieve payment proof, {}",
					e
				))
				.into());
			}
		}
	})?;
	Ok(())
}

/// Proof Verify Args
pub struct ProofVerifyArgs {
	pub input_file: String,
}

pub fn proof_verify<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ProofVerifyArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let mut proof_f = match File::open(&args.input_file) {
			Ok(p) => p,
			Err(e) => {
				let msg = format!(
					"Unable to open payment proof file at {}: {}",
					args.input_file, e
				);
				error!("{}", msg);
				return Err(ErrorKind::LibWallet(msg).into());
			}
		};
		let mut proof = String::new();
		proof_f
			.read_to_string(&mut proof)
			.map_err(|e| ErrorKind::LibWallet(format!("Unable to read proof data, {}", e)))?;
		// read
		let proof: PaymentProof = match json::from_str(&proof) {
			Ok(p) => p,
			Err(e) => {
				let msg = format!("{}", e);
				error!("Unable to parse payment proof file: {}", e);
				return Err(ErrorKind::LibWallet(msg).into());
			}
		};
		let result = api.verify_payment_proof(m, &proof);
		match result {
			Ok((iam_sender, iam_recipient)) => {
				println!("Payment proof's signatures are valid.");
				if iam_sender {
					println!("The proof's sender address belongs to this wallet.");
				}
				if iam_recipient {
					println!("The proof's recipient address belongs to this wallet.");
				}
				if !iam_recipient && !iam_sender {
					println!(
						"Neither the proof's sender nor recipient address belongs to this wallet."
					);
				}
				Ok(())
			}
			Err(e) => {
				error!("Proof not valid: {}", e);
				Err(ErrorKind::LibWallet(format!("Proof not valid: {}", e)).into())
			}
		}
	})?;
	Ok(())
}

pub fn dump_wallet_data<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	file_name: Option<String>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, _m| {
		let result = api.dump_wallet_data(file_name);
		match result {
			Ok(_) => {
				warn!("Data dump is finished, please check the logs for results",);
				Ok(())
			}
			Err(e) => {
				error!("Wallet Data dump failed: {}", e);
				Err(ErrorKind::LibWallet(format!("Wallet Data dump failed, {}", e)).into())
			}
		}
	})?;
	Ok(())
}
