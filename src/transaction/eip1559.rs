use ethereum_types::{H256, U256};
use rlp::{DecoderError, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

use crate::Bytes;

pub use super::eip2930::{AccessList, TransactionAction, TransactionSignature};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(
		scale_codec::Encode,
		scale_codec::Decode,
		scale_codec::DecodeWithMemTracking,
		scale_info::TypeInfo
	)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EIP1559Transaction {
	pub chain_id: u64,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub access_list: AccessList,
	pub signature: TransactionSignature,
}

impl EIP1559Transaction {
	pub fn hash(&self) -> H256 {
		let enc = rlp::encode(self);
		let mut out = alloc::vec![2u8];
		out.extend_from_slice(&enc);
		H256::from_slice(Keccak256::digest(&out).as_ref())
	}

	pub fn to_message(&self) -> EIP1559TransactionMessage {
		EIP1559TransactionMessage {
			chain_id: self.chain_id,
			nonce: self.nonce,
			max_priority_fee_per_gas: self.max_priority_fee_per_gas,
			max_fee_per_gas: self.max_fee_per_gas,
			gas_limit: self.gas_limit,
			action: self.action.clone(),
			value: self.value,
			input: self.input.clone(),
			access_list: self.access_list.clone(),
		}
	}
}

impl rlp::Encodable for EIP1559Transaction {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(12);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.max_priority_fee_per_gas);
		s.append(&self.max_fee_per_gas);
		s.append(&self.gas_limit);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.input);
		s.append_list(&self.access_list);

		let sig = &self.signature;
		s.append(&sig.odd_y_parity());
		s.append(&U256::from_big_endian(sig.r().as_bytes()));
		s.append(&U256::from_big_endian(sig.s().as_bytes()));
	}
}

impl rlp::Decodable for EIP1559Transaction {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.item_count()? != 12 {
			return Err(DecoderError::RlpIncorrectListLen);
		}

		let odd = rlp.val_at(9)?;
		let r_u: U256 = rlp.val_at(10)?;
		let s_u: U256 = rlp.val_at(11)?;

		let mut r_bytes = [0u8; 32];
		let mut s_bytes = [0u8; 32];
		r_u.to_big_endian(&mut r_bytes);
		s_u.to_big_endian(&mut s_bytes);

		let sig = TransactionSignature::new(
			odd,
			H256::from(r_bytes),
			H256::from(s_bytes),
		)
		.ok_or(DecoderError::Custom("Invalid transaction signature"))?;

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			nonce: rlp.val_at(1)?,
			max_priority_fee_per_gas: rlp.val_at(2)?,
			max_fee_per_gas: rlp.val_at(3)?,
			gas_limit: rlp.val_at(4)?,
			action: rlp.val_at(5)?,
			value: rlp.val_at(6)?,
			input: rlp.val_at(7)?,
			access_list: rlp.list_at(8)?,
			signature: sig,
		})
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EIP1559TransactionMessage {
	pub chain_id: u64,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub access_list: AccessList,
}

impl EIP1559TransactionMessage {
	pub fn hash(&self) -> H256 {
		let enc = rlp::encode(self);
		let mut out = alloc::vec![2u8];
		out.extend_from_slice(&enc);
		H256::from_slice(Keccak256::digest(&out).as_ref())
	}
}

impl rlp::Encodable for EIP1559TransactionMessage {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(9);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.max_priority_fee_per_gas);
		s.append(&self.max_fee_per_gas);
		s.append(&self.gas_limit);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.input);
		s.append_list(&self.access_list);
	}
}

impl From<EIP1559Transaction> for EIP1559TransactionMessage {
	fn from(t: EIP1559Transaction) -> Self {
		t.to_message()
	}
}