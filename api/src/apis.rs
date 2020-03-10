use std::sync::Arc;

use failure::Error;

use crate::core::core::Transaction;
use crate::util::Mutex;
use grin_wallet_libwallet::wallet_lock;
use grin_wallet_mwcmqs::tx_proof::TxProof;

use crate::keychain::Keychain;
use crate::libwallet::{ErrorKind, NodeClient, Slate, WalletInst, WalletLCProvider};

///added with mqs feature
pub fn process_receiver_initiated_slate<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	slate: &mut Slate,
	address: Option<String>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// reject by default unless wallet is set to auto accept invoices under a certain threshold
	//lock the wallet
	//	let max_auto_accept_invoice = self
	//		.max_auto_accept_invoice
	//		.ok_or(ErrorKind::DoesNotAcceptInvoices)?;

	//yang todo get this number from some config file.
	let max_auto_accept_invoice = 50000000000;

	if slate.amount > max_auto_accept_invoice {
		Err(ErrorKind::InvoiceAmountTooBig(slate.amount))?;
	}
	let active_account = "default";

	*slate = invoice_tx(
		wallet.clone(),
		Some(active_account.to_string()),
		slate,
		address.clone(),
		10,
		500,
		1,
		false,
		None,
	)?;

	tx_lock_outputs(wallet, slate, address, 1)?;

	Ok(())
}

fn invoice_tx<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	active_account: Option<String>,
	slate: &Slate,
	address: Option<String>,
	minimum_confirmations: u64,
	max_outputs: u32,
	num_change_outputs: u32,
	selection_strategy_is_use_all: bool,
	message: Option<String>,
) -> Result<Slate, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	let params = grin_wallet_libwallet::InitTxArgs {
		src_acct_name: active_account,
		amount: slate.amount,
		minimum_confirmations,
		max_outputs,
		num_change_outputs,
		/// If `true`, attempt to use up as many outputs as
		/// possible to create the transaction, up the 'soft limit' of `max_outputs`. This helps
		/// to reduce the size of the UTXO set and the amount of data stored in the wallet, and
		/// minimizes fees. This will generally result in many inputs and a large change output(s),
		/// usually much larger than the amount being sent. If `false`, the transaction will include
		/// as many outputs as are needed to meet the amount, (and no more) starting with the smallest
		/// value outputs.
		selection_strategy_is_use_all,
		message,
		/// Optionally set the output target slate version (acceptable
		/// down to the minimum slate version compatible with the current. If `None` the slate
		/// is generated with the latest version.
		target_slate_version: None,
		/// Number of blocks from current after which TX should be ignored
		ttl_blocks: None,
		/// If set, require a payment proof for the particular recipient
		payment_proof_recipient_address: None,
		address,
		/// If true, just return an estimate of the resulting slate, containing fees and amounts
		/// locked without actually locking outputs or creating the transaction. Note if this is set to
		/// 'true', the amount field in the slate will contain the total amount locked, not the provided
		/// transaction amount
		estimate_only: None,
		/// Sender arguments. If present, the underlying function will also attempt to send the
		/// transaction to a destination and optionally finalize the result
		send_args: None,
	};
	let slate =
		grin_wallet_libwallet::owner::process_invoice_tx(&mut **w, None, slate, params, false)?;

	Ok(slate)
}

// Lock slate outputs. In other words create output and transaction record at the DB.
fn tx_lock_outputs<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	slate: &Slate,
	address: Option<String>,
	participant_id: usize,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	grin_wallet_libwallet::owner::tx_lock_outputs(&mut **w, None, slate, address, participant_id)?;
	Ok(())
}

///added with mqs feature
pub fn process_sender_initiated_slate<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	address: Option<String>,
	slate: &mut Slate,
	key_id: Option<&str>,
	output_amounts: Option<Vec<u64>>,
	dest_acct_name: Option<&str>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let s = receive_tx(
		wallet,
		address,
		slate,
		None,
		key_id,
		output_amounts,
		dest_acct_name,
	)
	.map_err(|_| ErrorKind::GrinWalletReceiveError)?;
	*slate = s;
	Ok(())
}

fn receive_tx<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	address: Option<String>,
	slate: &mut Slate,
	message: Option<String>,
	key_id: Option<&str>,
	output_amounts: Option<Vec<u64>>,
	dest_acct_name: Option<&str>,
) -> Result<Slate, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	let s = grin_wallet_libwallet::foreign::receive_tx(
		&mut **w,
		None,
		slate,
		address,
		key_id,
		output_amounts,
		dest_acct_name,
		message,
		false,
	)?;
	Ok(s)
}

///added with mqs feature
pub fn finalize_slate<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	slate: &mut Slate,
	tx_proof: Option<&mut TxProof>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	verify_slate_messages(&slate).map_err(|_| ErrorKind::GrinWalletVerifySlateMessagesError)?;

	let should_post = finalize_tx(wallet.clone(), slate, tx_proof)
		.map_err(|_| ErrorKind::GrinWalletFinalizeError)?;

	if should_post {
		post_tx(wallet, &slate.tx, false).map_err(|_| ErrorKind::GrinWalletPostError)?;
	}
	Ok(())
}

///added with mqs feature
pub fn finalize_invoice_slate<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	slate: &mut Slate,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	verify_slate_messages(&slate).map_err(|_| ErrorKind::GrinWalletVerifySlateMessagesError)?;

	let should_post = finalize_invoice_tx(wallet.clone(), slate)
		.map_err(|_| ErrorKind::GrinWalletFinalizeError)?;

	if should_post {
		post_tx(wallet, &slate.tx, false).map_err(|_| ErrorKind::GrinWalletPostError)?;
	}
	Ok(())
}

fn verify_slate_messages(slate: &Slate) -> Result<(), Error> {
	slate.verify_messages()?;
	Ok(())
}

///added with mqs feature
pub fn finalize_tx<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	slate: &mut Slate,
	tx_proof: Option<&mut TxProof>,
) -> Result<bool, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	let (slate_res, context) = grin_wallet_libwallet::owner::finalize_tx(&mut **w, None, slate)?;
	*slate = slate_res;

	if tx_proof.is_some() {
		let mut proof = tx_proof.unwrap();
		proof.amount = context.amount;
		proof.fee = context.fee;
		for input in context.input_commits {
			proof.inputs.push(input.clone());
		}
		for output in context.output_commits {
			proof.outputs.push(output.clone());
		}

		proof.store_tx_proof(w.get_data_file_dir(), &slate.id.to_string())?;
	};

	Ok(true)
}

///added with mqs feature
pub fn finalize_invoice_tx<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	slate: &mut Slate,
) -> Result<bool, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	*slate = grin_wallet_libwallet::foreign::finalize_invoice_tx(&mut **w, None, slate)?;
	Ok(true)
}

fn post_tx<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	tx: &Transaction,
	fluff: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// let tx_hex = to_hex(ser::ser_vec(tx,ser::ProtocolVersion(1) ).unwrap());
	let client = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().clone()
	};
	grin_wallet_libwallet::owner::post_tx(&client, tx, fluff)?;

	Ok(())
}
