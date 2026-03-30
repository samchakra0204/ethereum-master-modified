use alloc::vec::Vec;

use ethereum_types::{H160, H256};

use crate::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(rlp::RlpEncodable, rlp::RlpDecodable)]
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
pub struct Log {
    pub address: H160,
    pub topics: Vec<H256>,
    pub data: Bytes,
}

impl Log {
    pub fn new(address: H160, topics: Vec<H256>, data: Bytes) -> Self {
        Self { address, topics, data }
    }

    pub fn is_empty(&self) -> bool {
        self.topics.is_empty() && self.data.is_empty()
    }
}