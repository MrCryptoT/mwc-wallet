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
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::Secp256k1;
use rand::{thread_rng, Rng};

use super::proofaddress;
use crate::error::{Error, ErrorKind};

use crate::encrypt;
use std::num::NonZeroU32;

/// Encripted message, used for Tx Proofs
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
	/// Destination dddress for that massage
	pub destination: proofaddress::ProvableAddress,
	/// Encrypted message (normally it is a slate)
	encrypted_message: String,
	/// salt value
	salt: String,
	/// Nonce value
	nonce: String,
}

// See comments at  mwc-wallet/impls/src/seed.rs
// Seed is encrypted exactlty the same way ...

impl EncryptedMessage {
	/// Construct new instance
	pub fn new(
		message: String,
		destination: &proofaddress::ProvableAddress,
		receiver_public_key: &PublicKey,
		secret_key: &SecretKey,
	) -> Result<EncryptedMessage, Error> {
		let secp = Secp256k1::new();
		let mut common_secret = receiver_public_key.clone();
		common_secret.mul_assign(&secp, secret_key).map_err(|e| {
			ErrorKind::TxProofGenericError(format!("Unable to encrypt message, {}", e))
		})?;
		let common_secret_ser = common_secret.serialize_vec(&secp, true);
		let common_secret_slice = &common_secret_ser[1..33];

		let salt: [u8; 8] = thread_rng().gen();
		let nonce: [u8; 12] = thread_rng().gen();
		let mut key = [0; 32];
		ring::pbkdf2::derive(
			&ring::digest::SHA512,
			NonZeroU32::new(100).unwrap(),
			&salt,
			common_secret_slice,
			&mut key,
		);
		let mut enc_bytes = message.as_bytes().to_vec();
		let suffix_len = encrypt::aead::CHACHA20_POLY1305.tag_len();
		for _ in 0..suffix_len {
			enc_bytes.push(0);
		}
		let sealing_key =
			encrypt::aead::SealingKey::new(&encrypt::aead::CHACHA20_POLY1305, &key)
				.map_err(|e| ErrorKind::TxProofGenericError(format!("Unable to encrypt, {}", e)))?;
		encrypt::aead::seal_in_place(&sealing_key, &nonce, &[], &mut enc_bytes, suffix_len)
			.map_err(|e| ErrorKind::TxProofGenericError(format!("Unable to encrypt, {}", e)))?;

		Ok(EncryptedMessage {
			destination: destination.clone(),
			encrypted_message: util::to_hex(enc_bytes),
			salt: util::to_hex(salt.to_vec()),
			nonce: util::to_hex(nonce.to_vec()),
		})
	}

	/// Build a key that suppose to match that message
	pub fn key(
		&self,
		sender_public_key: &PublicKey,
		secret_key: &SecretKey,
	) -> Result<[u8; 32], Error> {
		let salt = util::from_hex(&self.salt).map_err(|e| {
			ErrorKind::TxProofGenericError(format!(
				"Unable to decode salt from HEX {}, {}",
				self.salt, e
			))
		})?;

		let secp = Secp256k1::new();
		let mut common_secret = sender_public_key.clone();
		common_secret.mul_assign(&secp, secret_key).map_err(|e| {
			ErrorKind::TxProofGenericError(format!("Key manipulation error, {}", e))
		})?;
		let common_secret_ser = common_secret.serialize_vec(&secp, true);
		let common_secret_slice = &common_secret_ser[1..33];

		let mut key = [0; 32];
		ring::pbkdf2::derive(
			&ring::digest::SHA512,
			NonZeroU32::new(100).unwrap(),
			&salt,
			common_secret_slice,
			&mut key,
		);

		Ok(key)
	}

	/// Decrypt/verify message with a key
	pub fn decrypt_with_key(&self, key: &[u8; 32]) -> Result<String, Error> {
		let mut encrypted_message = util::from_hex(&self.encrypted_message).map_err(|e| {
			ErrorKind::TxProofGenericError(format!(
				"Unable decode message from HEX {}, {}",
				self.encrypted_message, e
			))
		})?;
		let nonce = util::from_hex(&self.nonce).map_err(|e| {
			ErrorKind::TxProofGenericError(format!(
				"Unable decode nonce from HEX {}, {}",
				self.nonce, e
			))
		})?;

		let opening_key = encrypt::aead::OpeningKey::new(&encrypt::aead::CHACHA20_POLY1305, key)
			.map_err(|e| ErrorKind::TxProofGenericError(format!("Unable to build a key, {}", e)))?;
		let decrypted_data =
			encrypt::aead::open_in_place(&opening_key, &nonce, &[], 0, &mut encrypted_message)
				.map_err(|e| {
					ErrorKind::TxProofGenericError(format!("Unable to decrypt the message, {}", e))
				})?;

		let res_msg = String::from_utf8(decrypted_data.to_vec()).map_err(|e| {
			ErrorKind::TxProofGenericError(format!("Decrypted message is corrupted, {}", e))
		})?;
		Ok(res_msg)
	}
}
