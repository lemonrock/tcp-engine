// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Represents a TCP segment, that is, a TCP fixed header, variable header TCP options and payload.
#[derive(Debug)]
#[repr(C, packed)]
pub struct TcpSegment
{
	tcp_fixed_header: TcpFixedHeader,

	tcp_options_and_payload: PhantomData<u8>,
}

impl TcpSegmentWithAuthenticationData for TcpSegment
{
	#[inline(always)]
	fn write_md5_option(options_data_pointer: usize, digest: [u8; 16]) -> usize
	{
		Self::write_option(options_data_pointer, AuthenticationOption::Md5SignatureOptionKind, AuthenticationOption::Md5SignatureOptionKnownLength, digest)
	}
	
	#[inline(always)]
	fn secure_hash_fixed_header(&self, hasher: &mut impl Digest)
	{
		self.tcp_fixed_header.secure_hash(hasher)
	}
	
	#[inline(always)]
	fn secure_hash_payload_data(&self, hasher: &mut impl Digest, padded_options_size: usize, payload_size: usize)
	{
		let pointer = self.payload_data_pointer(padded_options_size).as_ptr() as *const u8;
		hasher.input(unsafe { from_raw_parts(pointer, payload_size) })
	}
}

impl TcpSegment
{
	/// When processing an acknowledgment: RFC 793, Page 25: "First sequence number of a segment."
	///
	/// When data is received: RFC 793, Page 25: "First sequence number occupied by the incoming segment."
	///
	/// SEQ.
	#[inline(always)]
	pub fn SEQ(&self) -> WrappingSequenceNumber
	{
		self.tcp_fixed_header.sequence_number()
	}
	
	/// ACK.
	#[inline(always)]
	pub fn ACK(&self) -> WrappingSequenceNumber
	{
		self.tcp_fixed_header.acknowledgment_sequence_number()
	}
	
	/// WND.
	#[inline(always)]
	pub fn WND(&self) -> SegmentWindowSize
	{
		self.tcp_fixed_header.window_size()
	}

	/// RFC 793, page 25: "The number of octets occupied by the data in the segment (counting SYN and FIN)".
	///
	/// RFC 1122, Section 4.2.2.12 implies (poorly) that any data carried in a RST is an ASCII "explanation".
	/// TCP folklore seems to be that these are not considered part of the data stream.
	/// Hence we treat `SEG.LEN` of a RST as zero (0), even when there is a payload.
	#[inline(always)]
	pub fn LEN(&self, payload_size: usize) -> u32
	{
		let SEG = self;

		if SEG.all_flags().contains(Flags::Synchronize) || SEG.all_flags().contains(Flags::Finish)
		{
			1
		}
		else if SEG.all_flags().contains(Flags::Reset)
		{
			0
		}
		else
		{
			payload_size as u32
		}
	}
	
	/// Last sequence number.
	#[inline(always)]
	pub fn exclusive_end_sequence_number(&self, payload_length: usize) -> WrappingSequenceNumber
	{
		self.SEQ() + payload_length
	}

	/// Mutable reference to the fixed header.
	#[inline(always)]
	pub fn tcp_fixed_header_mutable(&mut self) -> &mut TcpFixedHeader
	{
		&mut self.tcp_fixed_header
	}
	
	/// Source port and destination port.
	#[inline(always)]
	pub fn source_port_destination_port(&self) -> SourcePortDestinationPort
	{
		self.tcp_fixed_header.source_port_destination_port()
	}
	
	/// All flag values.
	#[inline(always)]
	pub fn all_flags(&self) -> Flags
	{
		self.tcp_fixed_header.flags
	}
	
	/// Flags with only SYN, ACK, FIN or RST set.
	#[inline(always)]
	pub fn syn_ack_fin_rst_only_flags(&self) -> Flags
	{
		let mut flags = self.all_flags();
		flags.remove(Flags::ExplicitCongestionEcho | Flags::CongestionWindowReduced | Flags::Push | Flags::Urgent);
		flags
	}
	
	/// Flags with only SYN, ACK, FIN, RST, ECE, or CWR set.
	#[inline(always)]
	pub fn syn_ack_fin_rst_ece_cwr_only_flags(&self) -> Flags
	{
		let mut flags = self.all_flags();
		flags.remove(Flags::Push | Flags::Urgent);
		flags
	}

	/// Raw data length in bytes.
	#[inline(always)]
	pub fn raw_data_length_bytes(&self) -> u8
	{
		self.tcp_fixed_header.data_offset_reserved_bits_nonce_sum_flag.raw_data_length_bytes()
	}

	/// Are the TCP reserved bits or the (historic) Nonce Sum (NS) flag set?
	#[inline(always)]
	pub fn are_reserved_bits_set_or_has_historic_nonce_sum_flag(&self) -> bool
	{
		self.tcp_fixed_header.data_offset_reserved_bits_nonce_sum_flag.are_reserved_bits_set_or_has_historic_nonce_sum_flag()
	}

	/// Is the urgent pointer set?
	#[inline(always)]
	pub fn urgent_pointer_if_URG_flag_set_is_not_zero(&self) -> bool
	{
		self.tcp_fixed_header.urgent_pointer_if_URG_flag_set.is_not_zero()
	}

	/// Pointer to payload data after the fixed TCP header and options data.
	#[inline(always)]
	pub fn payload_data_pointer(&self, padded_options_size: usize) -> NonNull<u8>
	{
		unsafe { NonNull::new_unchecked(((&self.tcp_options_and_payload as *const PhantomData<u8> as *const u8 as usize) + padded_options_size) as *mut u8) }
	}

	/// Set all fields except check sum when sending this in a TCP segment to the network.
	#[inline(always)]
	pub fn set_for_send(&mut self, remote_port_local_port: RemotePortLocalPort, SEQ: WrappingSequenceNumber, ACK: WrappingSequenceNumber, padded_options_size: usize, flags: Flags, window_size: SegmentWindowSize)
	{
		self.tcp_fixed_header.set_for_send(remote_port_local_port, SEQ, ACK, padded_options_size, flags, window_size)
	}

	/// Set the RFC 1141 (RFC 1071) TCP check sum.
	#[inline(always)]
	pub fn set_check_sum(&mut self, check_sum: Rfc1141CompliantCheckSum)
	{
		self.tcp_fixed_header.checksum = check_sum.into();
	}

	/// RFC 3168 Section 6.1.2 Paragraph 5: "... the CWR bit in the TCP header SHOULD NOT be set on retransmitted packets".
	#[inline(always)]
	pub fn clear_congestion_window_reduced_flag(&mut self)
	{
		self.tcp_fixed_header.flags.remove(Flags::CongestionWindowReduced)
	}

	/// Pointer to start of TCP options data.
	#[inline(always)]
	pub fn options_data_pointer(&self) -> usize
	{
		&self.tcp_options_and_payload as *const PhantomData<u8> as *const u8 as usize
	}
	
	/// Write the maximum segment size TCP option.
	#[inline(always)]
	pub fn write_maximum_segment_size_option(options_data_pointer: usize, maximum_segment_size: u16) -> usize
	{
		Self::write_option(options_data_pointer, MaximumSegmentSizeOption::Kind, MaximumSegmentSizeOption::KnownLength, NetworkEndianU16::from_native_endian(maximum_segment_size))
	}
	
	/// Write the window scale TCP option.
	#[inline(always)]
	pub fn write_window_scale_option(options_data_pointer: usize, window_scale: u8) -> usize
	{
		Self::write_option(options_data_pointer, WindowScaleOption::Kind, WindowScaleOption::KnownLength, window_scale)
	}
	
	/// Write the selective acknowledgments (SACK) permitted TCP option.
	#[inline(always)]
	pub fn write_selective_acknowledgment_permitted_option(options_data_pointer: usize) -> usize
	{
		Self::write_option(options_data_pointer, SelectiveAcknowledgmentOption::SelectiveAcknowledgmentPermittedOptionKind, SelectiveAcknowledgmentOption::SelectiveAcknowledgmentPermittedOptionKnownLength, ())
	}

	/// Write the timestamps TCP option.
	#[inline(always)]
	pub fn write_timestamps_option(options_data_pointer: usize, timestamps_option: TimestampsOption) -> usize
	{
		Self::write_option(options_data_pointer, TimestampsOption::Kind, TimestampsOption::KnownLength, timestamps_option)
	}
	
	/// Reserve space for the MD5 TCP option.
	#[inline(always)]
	pub const fn reserve_space_for_md5_option(options_data_pointer: usize) -> usize
	{
		options_data_pointer + AuthenticationOption::Md5SignatureOptionKnownLength
	}

	/// Write the TCP Selective Acknowledgments (SACK) option.
	#[inline(always)]
	pub fn write_selective_acknowledgments_option(options_data_pointer: usize, selective_acknowledgments_block: SelectiveAcknowledgmentBlock) -> usize
	{
		Self::write_option(options_data_pointer, SelectiveAcknowledgmentOption::Kind, SelectiveAcknowledgmentOption::OneBlockLength, selective_acknowledgments_block)
	}

	#[inline(always)]
	fn options_size_is_not_a_multiple_of_four(options_size: usize) -> bool
	{
		debug_assert!(options_size <= 40, "options_size '{}' exceeds maximum of 40", options_size);
		options_size & 0b11 != 0
	}

	#[inline(always)]
	fn round_up_options_size_if_not_a_multiple_of_four(options_size: usize) -> usize
	{
		(options_size & !0b11) + 4
	}

	/// Round up options size to a multiple of four (4).
	#[inline(always)]
	pub fn round_up_options_size_to_multiple_of_four(options_size: usize) -> usize
	{
		if Self::options_size_is_not_a_multiple_of_four(options_size)
		{
			Self::round_up_options_size_if_not_a_multiple_of_four(options_size)
		}
		else
		{
			options_size
		}
	}
	
	/// Round up options size to a multiple of four (4) and set padding to zero.
	#[inline(always)]
	pub fn round_up_options_size_to_multiple_of_four_and_set_padding_to_zero(start_of_options_data_pointer: usize, end_of_options_data_pointer: usize) -> usize
	{
		let options_size = end_of_options_data_pointer - start_of_options_data_pointer;

		if Self::options_size_is_not_a_multiple_of_four(options_size)
		{
			let rounded_up_to_a_multiple_of_four = Self::round_up_options_size_if_not_a_multiple_of_four(options_size);

			let number_of_padding_bytes_to_set_to_zero = rounded_up_to_a_multiple_of_four - options_size;
			unsafe { (end_of_options_data_pointer as *mut u8).write_bytes(0x00, number_of_padding_bytes_to_set_to_zero) }

			rounded_up_to_a_multiple_of_four
		}
		else
		{
			options_size
		}
	}
	
	/// Layer 4 packet size.
	#[inline(always)]
	pub fn layer_4_packet_size(padded_options_size: usize, payload_size: usize) -> usize
	{
		size_of::<TcpFixedHeader>() + padded_options_size + payload_size
	}

	#[inline(always)]
	fn write_option<T: Sized>(options_data_pointer: usize, kind: u8, known_length: usize, value: T) -> usize
	{
		const MaximumKnownLength: usize = 40;

		debug_assert!(known_length <= MaximumKnownLength, "known_length '{}' exceeds maximum '{}'", known_length, MaximumKnownLength);

		unsafe
		{
			(options_data_pointer as *mut u8).write_unaligned(kind);
			((options_data_pointer + 1) as *mut u8).write_unaligned(known_length as u8);
			if size_of::<T>() != 0
			{
				((options_data_pointer + 2) as *mut T).write_unaligned(value);
			}
		}

		options_data_pointer + known_length
	}
}
