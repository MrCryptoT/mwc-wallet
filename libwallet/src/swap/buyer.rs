// Copyright 2019 The vault713 Developers
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

use super::message::*;
use super::swap::{publish_transaction, tx_add_input, tx_add_output, Swap};
use super::types::*;
use super::{is_test_mode, ErrorKind, Keychain, CURRENT_VERSION};
use crate::swap::multisig::{Builder as MultisigBuilder, ParticipantData as MultisigParticipant};
use crate::{NodeClient, ParticipantData as TxParticipant, Slate, SlateVersion, VersionedSlate};
use chrono::{TimeZone, Utc};
use grin_core::libtx::{build, proof, tx_fee};
use grin_keychain::{BlindSum, BlindingFactor, SwitchCommitmentType};
use grin_util::secp::aggsig;
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::secp::pedersen::RangeProof;
use rand::thread_rng;
use std::mem;
use uuid::Uuid;

/// Buyer API. Bunch of methods that cover buyer action for MWC swap
/// This party is Buying MWC and selling BTC
pub struct BuyApi {}

impl BuyApi {
	/// Accepting Seller offer and create Swap instance
	pub fn accept_swap_offer<K: Keychain>(
		keychain: &K,
		context: &Context,
		id: Uuid,
		offer: OfferUpdate,
		height: u64,
	) -> Result<Swap, ErrorKind> {
		let test_mode = is_test_mode();
		if offer.version != CURRENT_VERSION {
			return Err(ErrorKind::IncompatibleVersion(
				offer.version,
				CURRENT_VERSION,
			));
		}

		context.unwrap_buyer()?;

		// Multisig tx needs to be unlocked
		let lock_slate: Slate = offer.lock_slate.into();
		if lock_slate.lock_height > 0 {
			return Err(ErrorKind::InvalidLockHeightLockTx);
		}

		// Refund tx needs to be locked until at least 10 hours in the future
		let refund_slate: Slate = offer.refund_slate.into();
		// expecting at least half of the interval
		if refund_slate.lock_height < height + offer.mwc_lock_time_seconds / 2 / 60 {
			return Err(ErrorKind::InvalidLockHeightRefundTx);
		}

		// Start redeem slate
		let mut redeem_slate = Slate::blank(2);
		if test_mode {
			redeem_slate.id = Uuid::parse_str("78aa5af1-048e-4c49-8776-a2e66d4a460c").unwrap()
		}
		redeem_slate.fee = tx_fee(1, 1, 1, None);
		redeem_slate.height = height;
		redeem_slate.amount = offer.primary_amount.saturating_sub(redeem_slate.fee);

		redeem_slate.participant_data.push(offer.redeem_participant);

		let multisig = MultisigBuilder::new(
			2,
			offer.primary_amount,
			false,
			1,
			context.multisig_nonce.clone(),
			None,
		);

		let started = if test_mode {
			Utc.ymd(2019, 9, 4).and_hms_micro(21, 22, 33, 386997)
		} else {
			offer.start_time.clone()
		};

		let mut swap = Swap {
			id,
			idx: 0,
			version: CURRENT_VERSION,
			network: offer.network,
			role: Role::Buyer,
			seller_lock_first: offer.seller_lock_first,
			started,
			status: Status::Offered,
			primary_amount: offer.primary_amount,
			secondary_amount: offer.secondary_amount,
			secondary_currency: offer.secondary_currency,
			secondary_data: SecondaryData::Empty,
			redeem_public: None,
			participant_id: 1,
			multisig,
			lock_slate,
			lock_confirmations: None,
			refund_slate,
			redeem_slate,
			redeem_confirmations: None,
			adaptor_signature: None,
			required_mwc_lock_confirmations: offer.required_mwc_lock_confirmations,
			required_secondary_lock_confirmations: offer.required_secondary_lock_confirmations,
			mwc_lock_time_seconds: offer.mwc_lock_time_seconds,
			seller_redeem_time: offer.seller_redeem_time,
			message1: None,
			message2: None,
		};

		swap.redeem_public = Some(PublicKey::from_secret_key(
			keychain.secp(),
			&Self::redeem_secret(keychain, context)?,
		)?);

		Self::build_multisig(keychain, &mut swap, context, offer.multisig)?;
		Self::sign_lock_slate(keychain, &mut swap, context)?;
		Self::sign_refund_slate(keychain, &mut swap, context)?;

		Ok(swap)
	}

	/// Buyer builds swap.redeem_slate
	pub fn init_redeem<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		swap.expect_buyer()?;
		swap.expect(Status::Locked, false)?;

		Self::build_redeem_slate(keychain, swap, context)?;
		Self::calculate_adaptor_signature(keychain, swap, context)?;

		Ok(())
	}

	/// Finalize redeem slate with a data form RedeemUpdate
	pub fn redeem<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		redeem: RedeemUpdate,
	) -> Result<(), ErrorKind> {
		swap.expect_buyer()?;
		swap.expect(Status::InitRedeem, false)?;

		Self::finalize_redeem_slate(keychain, swap, context, redeem.redeem_participant)?;
		swap.status = Status::Redeem;

		Ok(())
	}

	/// Check the redeem confirmations and move to Complete state
	pub fn completed(swap: &mut Swap) -> Result<(), ErrorKind> {
		swap.expect_buyer()?;
		if !(swap.status == Status::Redeem || swap.status == Status::Completed) {
			return Err(ErrorKind::UnexpectedStatus(Status::Redeem, swap.status));
		}
		match swap.redeem_confirmations {
			Some(h) if h > 0 => {
				swap.status = Status::Completed;
				Ok(())
			}
			_ => Err(ErrorKind::UnexpectedAction(
				"Buyer Fn complete(), redeem_confirmations is not defined".to_string(),
			)),
		}
	}

	/// Generate a message to another party
	pub fn message(swap: &Swap) -> Result<Message, ErrorKind> {
		match swap.status {
			Status::Offered => Self::accept_offer_message(swap),
			Status::Locked => Self::init_redeem_message(swap),
			_ => Err(ErrorKind::UnexpectedAction(format!(
				"Buyer Fn message(), unexpected status {:?}",
				swap.status
			))),
		}
	}

	/// Update swap state after a message has been sent succesfully
	pub fn message_sent(swap: &mut Swap) -> Result<(), ErrorKind> {
		match swap.status {
			Status::Offered => swap.status = Status::Accepted,
			Status::Locked => swap.status = Status::InitRedeem,
			_ => {
				return Err(ErrorKind::UnexpectedAction(format!(
					"Buyer Fn message_sent(), unexpected status {:?}",
					swap.status
				)))
			}
		};

		Ok(())
	}

	/// Publish MWC transaction to the node
	pub fn publish_transaction<C: NodeClient>(
		node_client: &C,
		swap: &mut Swap,
		retry: bool,
	) -> Result<(), ErrorKind> {
		if retry {
			publish_transaction(node_client, &swap.redeem_slate.tx, false)?;
			swap.redeem_confirmations = Some(0);
			return Ok(());
		}

		match swap.status {
			Status::Redeem => {
				if swap.redeem_confirmations.is_some() {
					// Tx already published
					return Err(ErrorKind::UnexpectedAction(
						"Buyer Fn publish_transaction(), redeem_confirmations already defined"
							.to_string(),
					));
				}
				publish_transaction(node_client, &swap.redeem_slate.tx, false)?;
				swap.redeem_confirmations = Some(0);
				Ok(())
			}
			_ => Err(ErrorKind::UnexpectedAction(format!(
				"Buyer Fn publish_transaction(), unexpected status {:?}",
				swap.status
			))),
		}
	}

	/// Required action based on current swap state
	pub fn required_action<C: NodeClient>(
		node_client: &mut C,
		swap: &mut Swap,
	) -> Result<Action, ErrorKind> {
		let action = match swap.status {
			Status::Offered => Action::SendMessage(1),
			Status::Accepted => unreachable!(), // Should be handled by currency specific API
			Status::Locked => Action::SendMessage(2),
			Status::InitRedeem => Action::ReceiveMessage,
			Status::Redeem => {
				if swap.redeem_confirmations.is_none() {
					Action::PublishTx
				} else {
					// Update confirmations
					match swap.find_redeem_kernel(node_client)? {
						Some((_, h)) => {
							let height = node_client.get_chain_tip()?.0;
							swap.redeem_confirmations = Some(height.saturating_sub(h) + 1);
							swap.status = Status::Completed; // We are done
							Action::Complete
						}
						None => Action::ConfirmationRedeem,
					}
				}
			}
			_ => Action::None,
		};
		Ok(action)
	}

	/// Generate 'Accept offer' massage
	pub fn accept_offer_message(swap: &Swap) -> Result<Message, ErrorKind> {
		swap.expect(Status::Offered, false)?;

		let id = swap.participant_id;
		swap.message(Update::AcceptOffer(AcceptOfferUpdate {
			multisig: swap.multisig.export()?,
			redeem_public: swap.redeem_public.unwrap().clone(),
			lock_participant: swap.lock_slate.participant_data[id].clone(),
			refund_participant: swap.refund_slate.participant_data[id].clone(),
		}))
	}

	/// Generate 'InitRedeem' slate message
	pub fn init_redeem_message(swap: &Swap) -> Result<Message, ErrorKind> {
		swap.expect(Status::Locked, false)?;

		swap.message(Update::InitRedeem(InitRedeemUpdate {
			redeem_slate: VersionedSlate::into_version(
				swap.redeem_slate.clone(),
				SlateVersion::V2, // V2 should satify our needs, dont adding extra
			),
			adaptor_signature: swap.adaptor_signature.ok_or(ErrorKind::UnexpectedAction(
				"Buyer Fn init_redeem_message(), multisig is empty".to_string(),
			))?,
		}))
	}

	/// Secret that unlocks the funds on both chains
	pub fn redeem_secret<K: Keychain>(
		keychain: &K,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		let bcontext = context.unwrap_buyer()?;
		let sec_key = keychain.derive_key(0, &bcontext.redeem, SwitchCommitmentType::None)?;

		Ok(sec_key)
	}

	fn build_multisig<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		part: MultisigParticipant,
	) -> Result<(), ErrorKind> {
		let multisig_secret = swap.multisig_secret(keychain, context)?;
		let multisig = &mut swap.multisig;

		// Import participant
		multisig.import_participant(0, &part)?;
		multisig.create_participant(keychain.secp(), &multisig_secret)?;
		multisig.round_1_participant(0, &part)?;

		// Round 1 + round 2
		multisig.round_1(keychain.secp(), &multisig_secret)?;
		let common_nonce = swap.common_nonce(keychain.secp())?;
		let multisig = &mut swap.multisig;
		multisig.common_nonce = Some(common_nonce);
		multisig.round_2(keychain.secp(), &multisig_secret)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the lock slate
	fn lock_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		// Partial multisig output
		let sum = BlindSum::new().add_blinding_factor(BlindingFactor::from_secret_key(
			swap.multisig_secret(keychain, context)?,
		));
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn sign_lock_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let mut sec_key = Self::lock_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.lock_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot(
				"Buyer Fn sign_lock_slate(), lock slate participant data is already initialized"
					.to_string(),
			)
			.into());
		}

		// Add multisig output to slate (with invalid proof)
		let mut proof = RangeProof::zero();
		proof.plen = grin_util::secp::constants::MAX_PROOF_SIZE;

		tx_add_output(slate, swap.multisig.commit(keychain.secp())?, proof);

		// Sign slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.lock_nonce,
			swap.participant_id,
			None,
			false,
		)?;
		slate.fill_round_2(keychain, &sec_key, &context.lock_nonce, swap.participant_id)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the refund slate
	fn refund_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		// Partial multisig input
		let sum = BlindSum::new().sub_blinding_factor(BlindingFactor::from_secret_key(
			swap.multisig_secret(keychain, context)?,
		));
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn sign_refund_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let commit = swap.multisig.commit(keychain.secp())?;
		let mut sec_key = Self::refund_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.refund_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot("Buyer Fn sign_refund_slate(), refund slate participant data is already initialized".to_string()).into());
		}

		// Add multisig input to slate
		tx_add_input(slate, commit);

		// Sign slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.refund_nonce,
			swap.participant_id,
			None,
			false,
		)?;
		slate.fill_round_2(
			keychain,
			&sec_key,
			&context.refund_nonce,
			swap.participant_id,
		)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the redeem slate
	pub fn redeem_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		let bcontext = context.unwrap_buyer()?;

		// Partial multisig input, redeem output, offset
		let sum = BlindSum::new()
			.add_key_id(bcontext.output.to_value_path(swap.redeem_slate.amount))
			.sub_blinding_factor(BlindingFactor::from_secret_key(
				swap.multisig_secret(keychain, context)?,
			))
			.sub_blinding_factor(swap.redeem_slate.tx.offset.clone());
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn build_redeem_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let bcontext = context.unwrap_buyer()?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot(
				"Buyer Fn build_redeem_slate(), redeem slate participant data is not empty"
					.to_string(),
			));
		}

		// Build slate
		slate.fee = tx_fee(1, 1, 1, None);
		slate.amount = swap.primary_amount - slate.fee;
		let mut elems = Vec::new();
		elems.push(build::output(slate.amount, bcontext.output.clone()));
		slate
			.add_transaction_elements(keychain, &proof::ProofBuilder::new(keychain), elems)?
			.secret_key(keychain.secp())?;
		slate.tx.offset = if is_test_mode() {
			BlindingFactor::from_hex(
				"90de4a3812c7b78e567548c86926820d838e7e0b43346b1ba63066cd5cc7d999",
			)
			.unwrap()
		} else {
			BlindingFactor::from_secret_key(SecretKey::new(keychain.secp(), &mut thread_rng()))
		};

		// Add multisig input to slate
		tx_add_input(slate, swap.multisig.commit(keychain.secp())?);

		let mut sec_key = Self::redeem_tx_secret(keychain, swap, context)?;
		let slate = &mut swap.redeem_slate;

		// Add participant to slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.redeem_nonce,
			swap.participant_id,
			None,
			false,
		)?;

		Ok(())
	}

	fn finalize_redeem_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		part: TxParticipant,
	) -> Result<(), ErrorKind> {
		let id = swap.participant_id;
		let other_id = swap.other_participant_id();
		let sec_key = Self::redeem_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate;
		if slate
			.participant_data
			.get(id)
			.ok_or(ErrorKind::UnexpectedAction("Buyer Fn finalize_redeem_slate() redeem slate participant data is not initialized for this party".to_string()))?
			.is_complete()
		{
			return Err(ErrorKind::OneShot("Buyer Fn finalize_redeem_slate() redeem slate is already initialized".to_string()).into());
		}

		// Replace participant
		mem::replace(
			slate
				.participant_data
				.get_mut(other_id)
				.ok_or(ErrorKind::UnexpectedAction("Buyer Fn finalize_redeem_slate() redeem slate participant data is not initialized for other party".to_string()))?,
			part,
		);

		// Sign + finalize slate
		slate.fill_round_2(
			keychain,
			&sec_key,
			&context.redeem_nonce,
			swap.participant_id,
		)?;
		slate.finalize(keychain)?;

		Ok(())
	}

	fn calculate_adaptor_signature<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		// This function should only be called once
		if swap.adaptor_signature.is_some() {
			return Err(ErrorKind::OneShot(
				"Buyer calculate_adaptor_signature(), miltisig is already initialized".to_string(),
			));
		}

		let sec_key = Self::redeem_tx_secret(keychain, swap, context)?;
		let (pub_nonce_sum, pub_blind_sum, message) =
			swap.redeem_tx_fields(keychain.secp(), &swap.redeem_slate)?;

		let adaptor_signature = aggsig::sign_single(
			keychain.secp(),
			&message,
			&sec_key,
			Some(&context.redeem_nonce),
			Some(&Self::redeem_secret(keychain, context)?),
			Some(&pub_nonce_sum),
			Some(&pub_blind_sum),
			Some(&pub_nonce_sum),
		)?;
		swap.adaptor_signature = Some(adaptor_signature);

		Ok(())
	}
}
