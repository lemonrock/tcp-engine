// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// The fixed (ie not varying in length) part of a TCP segment header.
///
/// Excludes any TCP options.
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct TcpFixedHeader
{
	source_port_destination_port: SourcePortDestinationPort,
	sequence_number: NetworkEndianU32,
	acknowledgment_sequence_number: NetworkEndianU32,
	data_offset_reserved_bits_nonce_sum_flag: DataOffsetReservedBitsNonceSumFlag,
	flags: Flags,
	window_size: NetworkEndianU16,
	checksum: NetworkEndianU16,
	
	/// RFC 793, Glossary, Page 84: "A control field meaningful only when the URG bit is on.
	/// This field communicates the value of the urgent pointer which indicates the data octet associated with the sending user's urgent call".
	urgent_pointer_if_URG_flag_set: NetworkEndianU16,
}

impl TcpFixedHeader
{
	/// Set necessary fields for sending in an outbound netwoek packet.
	#[inline(always)]
	pub fn set_for_send(&mut self, remote_port_local_port: RemotePortLocalPort, SEQ: WrappingSequenceNumber, ACK: WrappingSequenceNumber, padded_options_size: usize, flags: Flags, window_size: SegmentWindowSize)
	{
		self.source_port_destination_port = remote_port_local_port.for_send();
		self.sequence_number = SEQ.into();
		self.acknowledgment_sequence_number = ACK.into();
		
		// RFC 3360 Section 2.1: "... the Reserved field should be zero when sent ... unless specified otherwise by future standards actions".
		// RFC 4727 Section 7.2: "There are not enough reserved bits to allocate any for experimentation".
		self.data_offset_reserved_bits_nonce_sum_flag = DataOffsetReservedBitsNonceSumFlag::from_padded_options_size(padded_options_size);
		
		self.flags = flags;
		self.window_size = window_size.into();
		self.checksum = NetworkEndianU16::Zero;
		self.urgent_pointer_if_URG_flag_set = NetworkEndianU16::Zero;
	}
	
	/// Cryptographically hash.
	#[inline(always)]
	pub fn secure_hash(&self, digester: &mut impl Digest)
	{
		digester.input(self.source_port_destination_port.source_port().bytes());
		digester.input(self.source_port_destination_port.destination_port().bytes());
		digester.input(self.sequence_number.bytes());
		digester.input(self.acknowledgment_sequence_number.bytes());
		digester.input(&[self.data_offset_reserved_bits_nonce_sum_flag.into()]);
		digester.input(&[self.flags.bits()]);
		digester.input(self.window_size.bytes());
		digester.input(NetworkEndianU16::Zero.bytes());
		digester.input(self.urgent_pointer_if_URG_flag_set.bytes());
	}
	
	/// Use this reference for a MD5 signature (clones).
	#[inline(always)]
	pub fn use_for_md5_signature(&self) -> Self
	{
		let mut clone = self.clone();
		clone.checksum = NetworkEndianU16::Zero;
		clone
	}
	
	/// size, excluding options, as u8.
	#[inline(always)]
	pub const fn u8_size_excluding_options() -> u8
	{
		size_of::<Self>() as u8
	}
	
	/// size, excluding options, as u16.
	#[inline(always)]
	pub const fn u16_size_excluding_options() -> u16
	{
		size_of::<Self>() as u16
	}
	
	/// source port and destination port.
	#[inline(always)]
	pub fn source_port_destination_port(&self) -> SourcePortDestinationPort
	{
		self.source_port_destination_port
	}
	
	/// SEQ.
	#[inline(always)]
	pub fn sequence_number(&self) -> WrappingSequenceNumber
	{
		WrappingSequenceNumber::from(self.sequence_number)
	}
	
	/// ACK.
	#[inline(always)]
	pub fn acknowledgment_sequence_number(&self) -> WrappingSequenceNumber
	{
		WrappingSequenceNumber::from(self.acknowledgment_sequence_number)
	}
	
	/// Segment window size.
	#[inline(always)]
	pub fn window_size(&self) -> SegmentWindowSize
	{
		SegmentWindowSize::from(self.window_size)
	}
}
