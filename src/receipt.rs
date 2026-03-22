use alloc::vec::Vec;

use bytes::BytesMut;
use ethereum_types::{Bloom, H256, U256};
use rlp::{Decodable, DecoderError, Rlp};

use crate::{
	enveloped::{EnvelopedDecodable, EnvelopedDecoderError, EnvelopedEncodable},
	log::Log,
};

#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(rlp::RlpEncodable, rlp::RlpDecodable)]
pub struct FrontierReceiptData {
	pub state_root: H256,
	pub used_gas: U256,
	pub logs_bloom: Bloom,
	pub logs: Vec<Log>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(rlp::RlpEncodable, rlp::RlpDecodable)]
pub struct EIP658ReceiptData {
	pub status_code: u8,
	pub used_gas: U256,
	pub logs_bloom: Bloom,
	pub logs: Vec<Log>,
}

pub type EIP2930ReceiptData = EIP658ReceiptData;
pub type EIP1559ReceiptData = EIP658ReceiptData;
pub type EIP7702ReceiptData = EIP658ReceiptData;

pub type ReceiptV0 = FrontierReceiptData;

impl EnvelopedEncodable for ReceiptV0 {
	fn type_id(&self) -> Option<u8> { None }
	fn encode_payload(&self) -> BytesMut { rlp::encode(self) }
}

impl EnvelopedDecodable for ReceiptV0 {
	type PayloadDecoderError = DecoderError;
	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		Ok(rlp::decode(bytes)?)
	}
}

pub type ReceiptV1 = EIP658ReceiptData;

impl EnvelopedEncodable for ReceiptV1 {
	fn type_id(&self) -> Option<u8> { None }
	fn encode_payload(&self) -> BytesMut { rlp::encode(self) }
}

impl EnvelopedDecodable for ReceiptV1 {
	type PayloadDecoderError = DecoderError;
	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		Ok(rlp::decode(bytes)?)
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptV2 {
	Legacy(EIP658ReceiptData),
	EIP2930(EIP2930ReceiptData),
}

impl EnvelopedEncodable for ReceiptV2 {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Legacy(_) => None,
			Self::EIP2930(_) => Some(1),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Legacy(r) | Self::EIP2930(r) => rlp::encode(r),
		}
	}
}

impl EnvelopedDecodable for ReceiptV2 {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		if bytes.is_empty() {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		}

		let rlp = Rlp::new(bytes);

		if rlp.is_list() {
			return Ok(Self::Legacy(Decodable::decode(&rlp)?));
		}

		let first = bytes[0];
		let s = &bytes[1..];

		match first {
			0x01 => Ok(Self::EIP2930(rlp::decode(s)?)),
			_ => Err(DecoderError::Custom("invalid receipt type").into()),
		}
	}
}

impl From<ReceiptV2> for EIP658ReceiptData {
	fn from(v: ReceiptV2) -> Self {
		match v {
			ReceiptV2::Legacy(r) | ReceiptV2::EIP2930(r) => r,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptV3 {
	Legacy(EIP658ReceiptData),
	EIP2930(EIP2930ReceiptData),
	EIP1559(EIP1559ReceiptData),
}

impl EnvelopedEncodable for ReceiptV3 {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Legacy(_) => None,
			Self::EIP2930(_) => Some(1),
			Self::EIP1559(_) => Some(2),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Legacy(r)
			| Self::EIP2930(r)
			| Self::EIP1559(r) => rlp::encode(r),
		}
	}
}

impl EnvelopedDecodable for ReceiptV3 {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		if bytes.is_empty() {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		}

		let rlp = Rlp::new(bytes);

		if rlp.is_list() {
			return Ok(Self::Legacy(Decodable::decode(&rlp)?));
		}

		let first = bytes[0];
		let s = &bytes[1..];

		match first {
			0x01 => Ok(Self::EIP2930(rlp::decode(s)?)),
			0x02 => Ok(Self::EIP1559(rlp::decode(s)?)),
			_ => Err(DecoderError::Custom("invalid receipt type").into()),
		}
	}
}

impl From<ReceiptV3> for EIP658ReceiptData {
	fn from(v: ReceiptV3) -> Self {
		match v {
			ReceiptV3::Legacy(r)
			| ReceiptV3::EIP2930(r)
			| ReceiptV3::EIP1559(r) => r,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptV4 {
	Legacy(EIP658ReceiptData),
	EIP2930(EIP2930ReceiptData),
	EIP1559(EIP1559ReceiptData),
	EIP7702(EIP7702ReceiptData),
}

impl EnvelopedEncodable for ReceiptV4 {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Legacy(_) => None,
			Self::EIP2930(_) => Some(1),
			Self::EIP1559(_) => Some(2),
			Self::EIP7702(_) => Some(4),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Legacy(r)
			| Self::EIP2930(r)
			| Self::EIP1559(r)
			| Self::EIP7702(r) => rlp::encode(r),
		}
	}
}

impl EnvelopedDecodable for ReceiptV4 {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		if bytes.is_empty() {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		}

		let rlp = Rlp::new(bytes);

		if rlp.is_list() {
			return Ok(Self::Legacy(Decodable::decode(&rlp)?));
		}

		let first = bytes[0];
		let s = &bytes[1..];

		match first {
			0x01 => Ok(Self::EIP2930(rlp::decode(s)?)),
			0x02 => Ok(Self::EIP1559(rlp::decode(s)?)),
			0x04 => Ok(Self::EIP7702(rlp::decode(s)?)),
			_ => Err(DecoderError::Custom("invalid receipt type").into()),
		}
	}
}

impl From<ReceiptV4> for EIP658ReceiptData {
	fn from(v: ReceiptV4) -> Self {
		match v {
			ReceiptV4::Legacy(r)
			| ReceiptV4::EIP2930(r)
			| ReceiptV4::EIP1559(r)
			| ReceiptV4::EIP7702(r) => r,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptAny {
	Frontier(FrontierReceiptData),
	EIP658(EIP658ReceiptData),
	EIP2930(EIP2930ReceiptData),
	EIP1559(EIP1559ReceiptData),
	EIP7702(EIP7702ReceiptData),
}

impl EnvelopedEncodable for ReceiptAny {
	fn type_id(&self) -> Option<u8> {
		match self {
			Self::Frontier(_) | Self::EIP658(_) => None,
			Self::EIP2930(_) => Some(1),
			Self::EIP1559(_) => Some(2),
			Self::EIP7702(_) => Some(4),
		}
	}

	fn encode_payload(&self) -> BytesMut {
		match self {
			Self::Frontier(r)
			| Self::EIP658(r)
			| Self::EIP2930(r)
			| Self::EIP1559(r)
			| Self::EIP7702(r) => rlp::encode(r),
		}
	}
}

impl EnvelopedDecodable for ReceiptAny {
	type PayloadDecoderError = DecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
		if bytes.is_empty() {
			return Err(EnvelopedDecoderError::UnknownTypeId);
		}

		let rlp = Rlp::new(bytes);

		if rlp.is_list() {
			if rlp.item_count()? == 4 {
				let first = rlp.at(0)?;
				if first.is_data() && first.data()?.len() <= 1 {
					return Ok(Self::Frontier(Decodable::decode(&rlp)?));
				} else {
					return Ok(Self::EIP658(Decodable::decode(&rlp)?));
				}
			}
			return Err(DecoderError::RlpIncorrectListLen.into());
		}

		let first = bytes[0];
		let s = &bytes[1..];

		match first {
			0x01 => Ok(Self::EIP2930(rlp::decode(s)?)),
			0x02 => Ok(Self::EIP1559(rlp::decode(s)?)),
			0x04 => Ok(Self::EIP7702(rlp::decode(s)?)),
			_ => Err(DecoderError::Custom("invalid receipt type").into()),
		}
	}
}