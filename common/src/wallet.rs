use crate::error_kind::ErrorKind;
use crate::mwcmq::MQSConfig;
use crate::tx_proof::TxProof;
use failure::Error;
use grin_wallet_impls::keychain::ExtKeychain;
use grin_wallet_impls::lifecycle::WalletSeed;
use grin_wallet_impls::node_clients::HTTPNodeClient;
use grin_wallet_impls::DefaultLCProvider;
use grin_wallet_impls::DefaultWalletImpl;
use grin_wallet_libwallet::WalletInst;
use std::sync::Arc;
use std::sync::Mutex;
/*
use uuid::Uuid;
use common::config::Wallet713Config;
use common::{ErrorKind, Error};

use grin_wallet_libwallet::{BlockFees, Slate, TxLogEntry, WalletInfo, CbData, WalletInst, OutputCommitMapping};
use grin_wallet_impls::lifecycle::WalletSeed;
use grin_core::core::Transaction;
use grin_util::secp::key::{ SecretKey, PublicKey };
use grin_wallet_impls::node_clients::HTTPNodeClient;
use grin_keychain::keychain::ExtKeychain;
use crate::common::{Arc, Mutex};

use crate::common::crypto::Hex;
use crate::wallet::types::TxProof;
use crate::wallet::api::api;
use grin_util::ZeroingString;
use grin_wallet_impls::{DefaultWalletImpl, DefaultLCProvider};
use grin_wallet_controller::display;
use std::sync::atomic::{AtomicBool, Ordering};
use grin_wallet_libwallet::api_impl::owner_updater;
use std::time::Duration;
use std::thread;
use std::thread::JoinHandle;
*/

pub struct Wallet {
	backend: Option<
		Arc<
			Mutex<
				Box<
					dyn WalletInst<
						'static,
						DefaultLCProvider<'static, HTTPNodeClient, ExtKeychain>,
						HTTPNodeClient,
						ExtKeychain,
					>,
				>,
			>,
		>,
	>,
	pub active_account: String,
}

impl Wallet {
	pub fn new() -> Self {
		Self {
			backend: None,
			active_account: "default".to_string(),
		}
	}

	pub fn is_locked(&self) -> bool {
		self.backend.is_none()
	}

	fn create_wallet_instance(
		&mut self,
		config: &MQSConfig,
		account: &str,
		passphrase: grin_wallet_util::grin_util::ZeroingString,
	) -> Result<(), Error> {
		TxProof::init_proof_backend(config.get_data_path_str()?.as_str())?;

		let node_client = HTTPNodeClient::new(&config.mwc_node_uri(), config.mwc_node_secret());

		let _ = WalletSeed::from_file(&config.get_data_path_str()?, passphrase.clone())?;

		let mut wallet = Box::new(
			DefaultWalletImpl::<'static, HTTPNodeClient>::new(node_client.clone()).unwrap(),
		)
			as Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<HTTPNodeClient, ExtKeychain>,
					HTTPNodeClient,
					ExtKeychain,
				>,
			>;
		let lc = wallet.lc_provider().unwrap();
		lc.set_top_level_directory(config.get_top_level_directory()?.as_str())?;
		lc.open_wallet(
			None,
			passphrase,
			false,
			false,
			Some(config.get_wallet_data_directory()?.as_str()),
		)?;
		let wallet_inst = lc.wallet_inst()?;
		wallet_inst.set_parent_key_id_by_name(account)?;
		self.backend = Some(Arc::new(Mutex::new(wallet)));

		Ok(())
	}

	pub fn lock(&mut self) {
		if self.backend.is_some() {
			let _ = self.get_wallet_instance().and_then(|wallet_inst| {
				let inst = wallet_inst.clone();
				let mut w_lock = inst.lock().unwrap();
				let _ = w_lock
					.lc_provider()
					.and_then(|lc_prov| lc_prov.close_wallet(None));
				Ok(())
			});
		}
		self.backend = None;
	}

	pub fn unlock(
		&mut self,
		config: &MQSConfig,
		account: &str,
		passphrase: grin_wallet_util::grin_util::ZeroingString,
	) -> Result<(), Error> {
		self.lock();
		self.create_wallet_instance(config, account, passphrase)
			.map_err(|_| ErrorKind::WalletUnlockFailed)?;
		Ok(())
	}

	// has full type because we don't want to deal with types inference.
	pub fn get_wallet_instance(
		&self,
	) -> Result<
		Arc<
			Mutex<
				Box<
					dyn WalletInst<
						'static,
						DefaultLCProvider<'static, HTTPNodeClient, ExtKeychain>,
						HTTPNodeClient,
						ExtKeychain,
					>,
				>,
			>,
		>,
		Error,
	> {
		if let Some(ref backend) = self.backend {
			Ok(backend.clone())
		} else {
			Err(ErrorKind::NoWallet)?
		}
	}
}
