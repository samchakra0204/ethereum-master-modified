use bytes::BytesMut;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvelopedDecoderError<T> {
	UnknownTypeId,
	Payload(T),
}

impl<T> From<T> for EnvelopedDecoderError<T> {
	fn from(e: T) -> Self {
		Self::Payload(e)
	}
}

pub trait EnvelopedEncodable {
	fn encode(&self) -> BytesMut {
		let type_id = self.type_id();
		let payload = self.encode_payload();

		let mut out = BytesMut::with_capacity(payload.len() + 1);

		if let Some(id) = type_id {
			assert!(id <= 0x7f);
			out.extend_from_slice(&[id]);
		}

		out.extend_from_slice(&payload);
		out
	}

	fn type_id(&self) -> Option<u8>;

	fn encode_payload(&self) -> BytesMut;
}

pub trait EnvelopedDecodable: Sized {
	type PayloadDecoderError;

	fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>>;
}