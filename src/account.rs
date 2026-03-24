use ethereum_types::{H256, U256};

#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(rlp::RlpEncodable, rlp::RlpDecodable)]
#[cfg_attr(
    feature = "with-scale",
    derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Account {
    pub bal: U256,
    pub nonce: U256,
    pub sroot: H256,
    pub chash: H256,
}