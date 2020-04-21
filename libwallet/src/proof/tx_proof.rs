// Copyright 2020 The Grin Developers
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

use crate::grin_util as util;
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::pedersen::Commitment;
use crate::grin_util::secp::{Secp256k1, Signature};

use super::crypto;
use super::message::EncryptedMessage;
use super::proofaddress::ProvableAddress;
use crate::error::{Error, ErrorKind};
use crate::Slate;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::{fs, path};

/// Dir name with proof files
pub const TX_PROOF_SAVE_DIR: &'static str = "saved_proofs";

/// Tx Proof - the mwc713 based proof that can be made for any address that is a public key.
#[derive(Debug, Serialize, Deserialize)]
pub struct TxProof {
	/// From address.
	pub address: ProvableAddress,
	/// Message that contain slate data
	pub message: String,
	/// Challenge
	pub challenge: String,
	/// Message & Challenge signature
	pub signature: Signature,
	/// Private key to decrypt the message
	pub key: [u8; 32],
	/// Placeholder
	pub amount: u64,
	/// Placeholder
	pub fee: u64,
	/// Placeholder
	pub inputs: Vec<Commitment>,
	/// Placeholder
	pub outputs: Vec<Commitment>,
}

impl TxProof {
	/// Verify this Proof
	pub fn verify_extract(
		&self,
		expected_destination: Option<&ProvableAddress>,
	) -> Result<(ProvableAddress, Slate), ErrorKind> {
		let mut challenge = String::new();
		challenge.push_str(self.message.as_str());
		challenge.push_str(self.challenge.as_str());

		let public_key = self.address.public_key().map_err(|e| {
			ErrorKind::TxProofGenericError(format!(
				"Unable to build public key from address {}, {}",
				self.address, e
			))
		})?;

		crypto::verify_signature(&challenge, &self.signature, &public_key)
			.map_err(|e| ErrorKind::TxProofVerifySignature(format!("{}", e)))?;

		let encrypted_message: EncryptedMessage =
			serde_json::from_str(&self.message).map_err(|e| {
				ErrorKind::TxProofGenericError(format!(
					"Fail to convert Json to EncryptedMessage {}, {}",
					self.message, e
				))
			})?;

		// TODO: at some point, make this check required
		let destination = &encrypted_message.destination;

		if expected_destination.is_some()
			&& destination.public_key != expected_destination.clone().unwrap().public_key
		{
			return Err(ErrorKind::TxProofVerifyDestination(
				expected_destination.unwrap().public_key.clone(),
				destination.public_key.clone(),
			));
		}

		let decrypted_message = encrypted_message.decrypt_with_key(&self.key).map_err(|e| {
			ErrorKind::TxProofGenericError(format!("Unable to decrypt message, {}", e))
		})?;

		let slate = Slate::deserialize_upgrade(&decrypted_message).map_err(|e| {
			ErrorKind::TxProofGenericError(format!(
				"Unable to build Slate form proof message, {}",
				e
			))
		})?;

		Ok((destination.clone(), slate))
	}

	/// Build proof data. massage suppose to be slate.
	pub fn from_response(
		from: &ProvableAddress,
		message: String,
		challenge: String,
		signature: String,
		secret_key: &SecretKey,
		expected_destination: &ProvableAddress,
	) -> Result<(Slate, TxProof), ErrorKind> {
		let address = from;

		let secp = Secp256k1::new();
		let signature = util::from_hex(&signature).map_err(|e| {
			ErrorKind::TxProofGenericError(format!(
				"Unable to build signature from HEX {}, {}",
				signature, e
			))
		})?;
		let signature = Signature::from_der(&secp, &signature).map_err(|e| {
			ErrorKind::TxProofGenericError(format!("Unable to build signature, {}", e))
		})?;

		let public_key = address.public_key().map_err(|e| {
			ErrorKind::TxProofGenericError(format!(
				"Unable to build public key for address {}, {}",
				address, e
			))
		})?;

		let encrypted_message: EncryptedMessage = serde_json::from_str(&message).map_err(|e| {
			ErrorKind::TxProofGenericError(format!(
				"Unable to build message fom HEX {}, {}",
				message, e
			))
		})?;
		let key = encrypted_message
			.key(&public_key, secret_key)
			.map_err(|e| {
				ErrorKind::TxProofGenericError(format!("Unable to build a signature, {}", e))
			})?;

		let proof = TxProof {
			address: address.clone(),
			message,
			challenge,
			signature,
			key,
			amount: 0,
			fee: 0,
			inputs: vec![],
			outputs: vec![],
		};

		let (_, slate) = proof.verify_extract(Some(expected_destination))?;

		Ok((slate, proof))
	}

	/// Init proff files storage
	pub fn init_proof_backend(data_file_dir: &str) -> Result<(), Error> {
		let stored_tx_proof_path = path::Path::new(data_file_dir).join(TX_PROOF_SAVE_DIR);
		fs::create_dir_all(&stored_tx_proof_path)
			.expect("Couldn't create wallet backend tx proof storage directory!");
		Ok(())
	}

	/// Check if Proofs are here
	pub fn has_stored_tx_proof(data_file_dir: &str, uuid: &str) -> Result<bool, Error> {
		let filename = format!("{}.proof", uuid);
		let path = path::Path::new(data_file_dir)
			.join(TX_PROOF_SAVE_DIR)
			.join(filename);
		let tx_proof_file = Path::new(&path).to_path_buf();
		Ok(tx_proof_file.exists())
	}

	/// Read stored proof file. data_file_dir
	pub fn get_stored_tx_proof(data_file_dir: &str, uuid: &str) -> Result<TxProof, Error> {
		let filename = format!("{}.proof", uuid);
		let path = path::Path::new(data_file_dir)
			.join(TX_PROOF_SAVE_DIR)
			.join(filename);
		let tx_proof_file = Path::new(&path).to_path_buf();
		if !tx_proof_file.exists() {
			return Err(ErrorKind::TransactionHasNoProof(
				tx_proof_file.to_str().unwrap_or(&"UNKNOWN").to_string(),
			)
			.into());
		}
		let mut tx_proof_f = File::open(tx_proof_file)?;
		let mut content = String::new();
		tx_proof_f.read_to_string(&mut content)?;
		Ok(serde_json::from_str(&content).map_err(|e| {
			ErrorKind::TxProofGenericError(format!("Unable to Build TxProof from Json, {}", e))
		})?)
	}

	/// Store tx proof at the file.
	pub fn store_tx_proof(&self, data_file_dir: &str, uuid: &str) -> Result<(), Error> {
		let filename = format!("{}.proof", uuid);
		let path = path::Path::new(data_file_dir)
			.join(TX_PROOF_SAVE_DIR)
			.join(filename);
		let path_buf = Path::new(&path).to_path_buf();
		let mut stored_tx = File::create(path_buf)?;
		let proof_ser = serde_json::to_string(self).map_err(|e| {
			ErrorKind::TxProofGenericError(format!("Unable to conver TxProof to Json, {}", e))
		})?;
		stored_tx.write_all(&proof_ser.as_bytes())?;
		stored_tx.sync_all()?;
		Ok(())
	}
}
