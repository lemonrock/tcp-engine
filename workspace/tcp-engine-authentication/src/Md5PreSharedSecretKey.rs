// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A pre-shared secret key of maximum length 80 bytes and a minimum of 1 byte for MD5 signature protection of TCP segments.
///
/// Whilst MD5 signature protection is officially obsolete, it is still the only widely used and thus available means for authentication of TCP segment data in hostile environments.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Md5PreSharedSecretKey
{
	incoming_key_bytes: ArrayVec<[u8; Md5PreSharedSecretKey::Md5PreSharedSecretKeyMaximumLength]>,
	outgoing_key_bytes: ArrayVec<[u8; Md5PreSharedSecretKey::Md5PreSharedSecretKeyMaximumLength]>,
}

impl Md5PreSharedSecretKey
{
	/// Maximum MD5 pre-shared secret key length.
	///
	/// FreeBSD uses a maximum of 80.
	pub const Md5PreSharedSecretKeyMaximumLength: usize = 128;

	/// Create a new instance.
	#[inline(always)]
	pub fn new(incoming_key_bytes: ArrayVec<[u8; Self::Md5PreSharedSecretKeyMaximumLength]>, outgoing_key_bytes: ArrayVec<[u8; Self::Md5PreSharedSecretKeyMaximumLength]>) -> Self
	{
		assert!(incoming_key_bytes.len() > 0, "incoming_key_bytes is empty");
		assert!(outgoing_key_bytes.len() > 0, "outgoing_key_bytes is empty");

		Md5PreSharedSecretKey
		{
			incoming_key_bytes,
			outgoing_key_bytes,
		}
	}
	
	/// Write the MD5 option into previously reserved option space in a TCP segment.
	#[inline(always)]
	pub fn write_md5_option_into_previously_reserved_space<Address: InternetProtocolAddress, TcpSegment: TcpSegmentWithAuthenticationData>(&self, source_internet_protocol_address: &Address, destination_internet_protocol_address: &Address, padded_options_size: usize, payload_size: usize, our_tcp_segment: &mut TcpSegment, previously_reserved_space_options_data_pointer: usize) -> usize
	{
		let digest = self.compute_digest(source_internet_protocol_address, destination_internet_protocol_address, padded_options_size, payload_size, our_tcp_segment, &self.outgoing_key_bytes);
		TcpSegment::write_md5_option(previously_reserved_space_options_data_pointer, digest)
	}

	/// Is the authentication option data valid?
	#[inline(always)]
	#[allow(non_snake_case)]
	pub fn is_invalid<Address: InternetProtocolAddress>(&self, received_digest: NonNull<u8>, source_internet_protocol_address: &Address, destination_internet_protocol_address: &Address, padded_options_size: usize, payload_size: usize, SEG: &impl TcpSegmentWithAuthenticationData) -> bool
	{
		let computed_digest = self.compute_digest(source_internet_protocol_address, destination_internet_protocol_address, padded_options_size, payload_size, SEG, &self.incoming_key_bytes);

		let computed_digest_pointer = computed_digest.as_ptr() as usize;
		let received_digest_pointer = received_digest.as_ptr() as usize;

		unsafe { *(computed_digest_pointer as *const u128) != *(received_digest_pointer as *const u128) }
	}

	#[inline(always)]
	fn compute_digest<Address: InternetProtocolAddress>(&self, source_internet_protocol_address: &Address, destination_internet_protocol_address: &Address, padded_options_size: usize, payload_size: usize, tcp_segment: &impl TcpSegmentWithAuthenticationData, pre_shared_secret_key_bytes: &ArrayVec<[u8; Self::Md5PreSharedSecretKeyMaximumLength]>) -> [u8; 16]
	{
		const TcpFixedHeaderLength: usize = 20;
		let tcp_segment_length = TcpFixedHeaderLength + padded_options_size + payload_size;

		// RFC 2385 Section 2.0: "Every segment sent on a TCP connection to be protected against spoofing will contain the 16-byte MD5 digest produced by applying the MD5 algorithm to these items in the following order".
		let mut hasher = Md5::default();

		// "1. the TCP pseudo-header (in the order: source IP address, destination IP address, zero-padded protocol number, and segment length)".
		InternetProtocolAddress::secure_hash(&mut hasher, source_internet_protocol_address, destination_internet_protocol_address, Layer4ProtocolNumber::Tcp, tcp_segment_length);

		// "2. the TCP header, excluding options, and assuming a checksum of zero".
		tcp_segment.secure_hash_fixed_header(&mut hasher);

		// "3. the TCP segment data (if any)".
		tcp_segment.secure_hash_payload_data(&mut hasher, padded_options_size, payload_size);

		// "4. an independently-specified key or password, known to both TCPs and presumably connection-specific".
		hasher.input(pre_shared_secret_key_bytes.as_slice());

		hasher.hash()
	}
}
