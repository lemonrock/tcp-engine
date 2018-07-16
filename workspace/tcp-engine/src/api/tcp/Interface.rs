// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Represents an interface to an ethernet device.
pub struct Interface<TCBA: TransmissionControlBlockAbstractions>
{
	transmission_control_block_abstractions: TCBA,
	maximum_segment_size_table: MaximumSegmentSizeTable<TCBA::Address, TCBA::PMTUTable>,
	incoming_segment_processor: v,
	listening_server_port_combination_validity: PortCombinationValidity,
	local_internet_protocol_address: TCBA::Address,
	transmission_control_blocks: TransmissionControlBlocks<TCBA, TransmissionControlBlock<TCBA>>,
	syn_cookie_protection: SynCookieProtection,
	alarms: Alarms<TCBA>,
	authentication_pre_shared_secret_keys: AuthenticationPreSharedSecretKeys,
}

/// Public API.
impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	/// Creates a new instance.
	///
	/// Below calling this, it is important that the `libnuma` method `numa_set_localalloc()` has been called, so that allocation is local to the allocating CPU.
	#[inline(always)]
	pub fn new(transmission_control_block_abstractions: TCBA, path_maximum_transmission_unit_table: TCBA::PMTUTable, check_sum_layering: CheckSumLayering, listening_server_port_combination_validity: PortCombinationValidity, local_internet_protocol_address: TCBA::Address, transmission_control_blocks_map_capacity: usize, maximum_recent_connections_capacity: usize, authentication_pre_shared_secret_keys: AuthenticationPreSharedSecretKeys) -> Self
	{
		const SendBufferSize: usize = 256 * 1024;
		
		let now = Tick::now();
		
		Self
		{
			transmission_control_block_abstractions,
			maximum_segment_size_table: MaximumSegmentSizeTable::new(path_maximum_transmission_unit_table),
			incoming_segment_processor: IncomingSegmentProcessor
			{
				check_sum_layering,
			},
			listening_server_port_combination_validity,
			local_internet_protocol_address,
			transmission_control_blocks: TransmissionControlBlocks::new(transmission_control_blocks_map_capacity, maximum_recent_connections_capacity),
			syn_cookie_protection: SynCookieProtection::new(now),
			alarms: Alarms::new(now),
			authentication_pre_shared_secret_keys,
		}
	}
	
	/// Progresses alarms and returns a monotonic millisecond timestamp that can be used as an input to `incoming_segment()`.
	#[inline(always)]
	pub fn progress_alarms(&self) -> MonotonicMillisecondTimestamp
	{
		self.alarms.progress(self)
	}
	
	#[inline(always)]
	pub fn new_outbound_connection(&self, remote_internet_protocol_address: TCBA::Address, remote_port: NetworkEndianU16, now: MonotonicMillisecondTimestamp, explicit_congestion_notification_supported: bool, connection_time_out: MillisecondDuration) -> Result<(), ()>
	{
		if self.transmission_control_blocks.at_maximum_capacity()
		{
			return Err(())
		}
		
		let (packet, our_tcp_segment) = self.create_for_tcp_segment(&remote_internet_protocol_address)?;
		
		let transmission_control_block = self.transmission_control_blocks.new_transmission_control_block_for_outgoing_client_connection(remote_internet_protocol_address, remote_port, now, explicit_congestion_notification_supported, connection_time_out, &self.listening_server_port_combination_validity, &self.authentication_pre_shared_secret_keys, &self.maximum_segment_size_table, &self.local_internet_protocol_address)?;
		
		self.send_synchronize(packet, our_tcp_segment, transmission_control_block, now);
		
		Ok(())
	}
	
	/// NOTE: RFC 2675 IPv6 jumbograms are not supported.
	///
	/// This logic DOES NOT validate:-
	///
	/// * that source and destination addreses are permitted, eg are not multicast (this is the responsibility of lower layers);
	/// * that the source and destination addresses (and ports) are not the same.
	///
	/// `layer_4_packet_size` is NOT the same as the IPv6 payload size; in this case, it is the IPv6 payload size LESS the extensions headers size.
	#[inline(always)]
	pub fn process_incoming_segment(&self, now: MonotonicMillisecondTimestamp, packet: TCBA::Packet, layer_4_packet_size: usize)
	{
		self.incoming_segment_processor.process_incoming_segment::<ParsedTcpSegment, Self>::(now, packet, layer_4_packet_size, self)
	}
}

/// Incoming segments.
impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	#[inline(always)]
	pub(crate) fn validate_syncookie(&self, remote_internet_protocol_address: &TCBA::Address, SEG: &ParsedTcpSegment<TCBA>) -> Result<ParsedSynCookie, ()>
	{
		self.syn_cookie_protection.validate_syncookie_in_acknowledgment(&self.local_internet_protocol_address, remote_internet_protocol_address, SEG.ACK, SEG.SEQ, SEG.source_port_destination_port())
	}
}

/// Transmission control blocks.
impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	#[inline(always)]
	pub(crate) fn new_transmission_control_block_for_incoming_segment(&self, source_internet_protocol_address: &TCBA::Address, SEG: &ParsedTcpSegment<TCBA>, tcp_options: &TcpOptions, parsed_syncookie: ParsedSynCookie, now: MonotonicMillisecondTimestamp, md5_authentication_key: Option<Rc<Md5PreSharedSecretKey>>) -> &mut TransmissionControlBlock<TCBA>
	{
		self.transmission_control_blocks.new_transmission_control_block_for_incoming_segment(source_internet_protocol_address, SEG.SEG, SEG.WND, tcp_options, parsed_syncookie, now, md5_authentication_key, &self.maximum_segment_size_table)
	}
	
	#[inline(always)]
	pub(crate) fn destroy_transmission_control_block(&self, key: &TransmissionControlBlockKey<TCBA::Address>, now: MonotonicMillisecondTimestamp)
	{
		let transmission_control_block = self.transmission_control_blocks.remove_transmission_control_block(key, now);
		transmission_control_block.destroying(self, self.alarms())
	}
}

/// Maximum Segment Size (MSS).
impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	#[inline(always)]
	pub(crate) fn maximum_segment_size_to_send_to_remote(&self, their_maximum_segment_size_options: Option<MaximumSegmentSizeOption>, remote_internet_protocol_address: &TCBA::Address) -> u16
	{
		self.maximum_segment_size_table.maximum_segment_size_to_send_to_remote(their_maximum_segment_size_options, remote_internet_protocol_address)
	}
}

/// Alarms and time outs.
impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	#[inline(always)]
	pub(crate) fn alarms(&self) -> &Alarms<TCBA>
	{
		&self.alarms
	}
	
	#[inline(always)]
	pub(crate) fn maximum_zero_window_probe_time_exceeded(&self, time_that_has_elapsed_since_send_window_last_updated: MillisecondDuration) -> bool
	{
		self.alarms.maximum_zero_window_probe_time_exceeded(time_that_has_elapsed_since_send_window_last_updated)
	}
}

/// Authentication.
impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	#[inline(always)]
	pub(crate) fn authentication_is_required(&self, remote_internet_protocol_address: &Address, remote_port_local_port: RemotePortLocalPort) -> bool
	{
		self.authentication_pre_shared_secret_keys.authentication_is_required(remote_internet_protocol_address, remote_port_local_port.local_port())
	}
	
	#[inline(always)]
	fn find_md5_authentication_key(&self, remote_internet_protocol_address: &Address, remote_port_local_port: RemotePortLocalPort) -> Option<&Rc<Md5PreSharedSecretKey>>
	{
		self.authentication_pre_shared_secret_keys.find_md5_authentication_key(remote_internet_protocol_address, remote_port_local_port.local_port())
	}
}

/// Sending.
impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	#[inline(always)]
	fn reserve_space_for_m5_option(options_data_pointer: usize, md5_authentication_key: Option<&Rc<Md5PreSharedSecretKey>>) -> (usize, usize)
	{
		if md5_authentication_key.is_some()
		{
			previously_reserved_space_options_data_pointer = options_data_pointer;
			(TcpSegment::reserve_space_for_md5_option(options_data_pointer), previously_reserved_space_options_data_pointer)
		}
		else
		{
			(options_data_pointer, 0)
		}
	}
	
	fn send_synchronize(&self, packet: TCBA::Packet, our_tcp_segment: &mut TcpSegment, transmission_control_block: &mut impl SendPacketTransmissionControlBlock<TCBA::Address>, now: MonotonicMillisecondTimestamp)
	{
		let remote_internet_protocol_address = transmission_control_block.remote_internet_protocol_address();
		let explicit_congestion_notification_supported = transmission_control_block.explicit_congestion_notification_supported();
		let md5_authentication_key = transmission_control_block.md5_authentication_key();
		
		let start_of_options_data_pointer = our_tcp_segment.options_data_pointer();
		
		let (end_of_options_data_pointer, previously_reserved_space_options_data_pointer) =
		{
			let mut options_data_pointer = start_of_options_data_pointer;
			options_data_pointer = TcpSegment::write_maximum_segment_size_option(transmission_control_block.our_offered_maximum_segment_size_when_initiating_connections());
			options_data_pointer = TcpSegment::write_window_scale_option(InitialWindowSize::Scale);
			options_data_pointer = TcpSegment::write_selective_acknowledgment_permitted_option(options_data_pointer);
			options_data_pointer = transmission_control_block.write_timestamping_option(options_data_pointer, now);
			Self::reserve_space_for_m5_option(options_data_pointer, md5_authentication_key)
		};
		
		let (padded_options_size, layer_4_packet_size) = TcpSegment::round_up_options_size_to_multiple_of_four_and_set_padding_to_zero(start_of_options_data_pointer, end_of_options_data_pointer);
		
		// TODO: Any payload writes (only if we use TCP fast-open).
		let payload_size = 0;
		
		let layer_4_packet_size = TcpSegment::layer_4_packet_size(padded_options_size, payload_size);
		
		{
			let flags = if explicit_congestion_notification_supported
			{
				Flags::SynchronizeExplicitCongestionEchoCongestionWindowReduced
			}
			else
			{
				Flags::Synchronize
			};
			
			let ISS = transmission_control_block.SND_UNA();
			our_tcp_segment.set_for_send(transmission_control_block.remote_port_local_port(), ISS, WrappingSequenceNumber::Zero, padded_options_size, flags, InitialWindowSize::Segment);
			
			self.check_sum_layering.calculate_in_software_and_set_if_required(our_tcp_segment, layer_4_packet_size, &self.local_internet_protocol_address, transmission_control_block.remote_internet_protocol_address());
		}
		
		if let Some(md5_authentication_key) = md5_authentication_key
		{
			md5_authentication_key.deref().write_md5_option_into_previously_reserved_space(&self.local_internet_protocol_address, remote_internet_protocol_address, padded_options_size, payload_size, our_tcp_segment, previously_reserved_space_options_data_pointer);
		}
		
		packet.set_layer_4_payload_length(layer_4_packet_size);
		
		transmission_control_block.transmitted(now, ISS, payload_size as u32, flags);
		
		self.send_packet(packet);
	}
	
	pub(crate) fn send_synchronize_acknowledgment(&self, now: MonotonicMillisecondTimestamp, packet: TCBA::Packet, remote_internet_protocol_address: &TCBA::Address, SEG: &ParsedTcpSegment, their_maximum_segment_size: Option<MaximumSegmentSizeOption>, their_window_scale: Option<WindowScaleOption>, their_selective_acknowledgment_permitted: bool, their_timestamp: Option<TimestampsOption>, explicit_congestion_notification_supported: bool, md5_authentication_key: Option<&Rc<Md5PreSharedSecretKey>>)
	{
		let mut our_tcp_segment = self.reuse_reversing_source_and_destination_addresses_for_tcp_segment(packet);
		
		let start_of_options_data_pointer = our_tcp_segment.options_data_pointer();
		
		let (end_of_options_data_pointer, previously_reserved_space_options_data_pointer) =
		{
			let mut options_data_pointer = start_of_options_data_pointer;
			let mut previously_reserved_space_options_data_pointer = 0;
			
			options_data_pointer = TcpSegment::write_maximum_segment_size_option(self.maximum_segment_size_to_send_to_remote(their_maximum_segment_size, remote_internet_protocol_address));
			
			if likely!(their_window_scale.is_some())
			{
				options_data_pointer = TcpSegment::write_window_scale_option(InitialWindowSize::Scale)
			}
			
			if likely!(their_selective_acknowledgment_permitted)
			{
				options_data_pointer = TcpSegment::write_selective_acknowledgment_permitted_option(options_data_pointer)
			}
			
			if let Some(their_timestamp) = their_timestamp
			{
				options_data_pointer = TcpSegment::write_timestamps_option(options_data_pointer, Timestamping::synflood_synchronize_acknowledgment_timestamps_option(their_timestamp.TSval))
			}
			
			Self::reserve_space_for_m5_option(options_data_pointer, md5_authentication_key)
		};
		
		let (padded_options_size, layer_4_packet_size) = TcpSegment::round_up_options_size_to_multiple_of_four_and_set_padding_to_zero(start_of_options_data_pointer, end_of_options_data_pointer);
		
		// TODO: Any payload writes (only if we use TCP fast-open).
		let payload_size = 0;
		
		let layer_4_packet_size = TcpSegment::layer_4_packet_size(padded_options_size, payload_size);
		
		{
			let syncookie = self.syn_cookie_protection.create_syn_cookie_for_synchronize_acnowledgment(now, &self.local_internet_protocol_address, remote_internet_protocol_address, SEG.SEQ, SEG.source_port_destination_port(), their_maximum_segment_size, their_window_scale, their_selective_acknowledgment_permitted, explicit_congestion_notification_supported);
			
			let flags = if explicit_congestion_notification_supported
			{
				Flags::SynchronizeAcknowledgmentExplicitCongestionEcho
			}
			else
			{
				Flags::SynchronizeAcknowledgment
			};
			
			our_tcp_segment.set_for_send(SEG.remote_port_local_port(), syncookie, SEG.SEQ + 1, padded_options_size, flags, InitialWindowSize::Segment);
			
			self.check_sum_layering.calculate_in_software_and_set_if_required(our_tcp_segment, layer_4_packet_size, &self.local_internet_protocol_address, transmission_control_block.remote_internet_protocol_address());
		}
		
		if let Some(md5_authentication_key) = md5_authentication_key
		{
			md5_authentication_key.deref().write_md5_option_into_previously_reserved_space(&self.local_internet_protocol_address, remote_internet_protocol_address, padded_options_size, payload_size, our_tcp_segment, previously_reserved_space_options_data_pointer);
		}
		
		packet.set_layer_4_payload_length(layer_4_packet_size);
		
		// TODO: transmission_control_block.transmitted(packet, our_tcp_segment, payload_size, now) if using TCP fast-open
		
		self.send_packet(packet);
	}
	
	#[inline(always)]
	pub(crate) fn send_final_acknowledgment_of_three_way_handshake(&self, packet: TCBA::Packet, transmission_control_block: &mut impl SendPacketTransmissionControlBlock<TCBA::Address>, now: MonotonicMillisecondTimestamp, mut flags: Flags, SEQ: WrappingSequenceNumber, ACK: WrappingSequenceNumber)
	{
		transmission_control_block.update_Last_ACK_sent(ACK);
		self.send_empty(packet, self.reuse_reversing_source_and_destination_addresses_for_tcp_segment(packet), transmission_control_block, now, flags, SEQ, ACK, None);
	}
	
	#[inline(always)]
	pub(crate) fn send_acknowledgment(&self, packet: TCBA::Packet, transmission_control_block: &mut impl SendPacketTransmissionControlBlock<TCBA::Address>, now: MonotonicMillisecondTimestamp, flags: Flags, SEQ: WrappingSequenceNumber, ACK: WrappingSequenceNumber)
	{
		let flags = transmission_control_block.add_explicit_congestion_echo_flag_to_acknowledgment_if_appropriate(flags);
		
		transmission_control_block.update_Last_ACK_sent(ACK);
		self.send_empty(packet, self.reuse_reversing_source_and_destination_addresses_for_tcp_segment(packet), transmission_control_block, now, flags, SEQ, ACK, None);
	}
	
	/// Keep-Alive probes have:-
	///
	/// * a segment size of zero (or, for some legacy stacks, one);
	/// * a sequence number:
	///   * For FreeBSD, SND.UNA - 1, which causes the segment to lie outside the receive window and requires the remote to respond (Processing Incoming Segment 4.1.3 or RFC 5961 Section 5.2 will cause this to happen).
	///   * For PicoTCP, SND.NXT - 1, which should force a duplicate acknowledgment.
	///
	/// A remote should then respond with with either a Acknowledgment or a Reset (if the connection is dead).
	#[inline(always)]
	pub(crate) fn send_keep_alive_probe_without_packet_to_reuse(&self, transmission_control_block: &mut impl SendPacketTransmissionControlBlock<TCBA::Address>, now: MonotonicMillisecondTimestamp) -> Result<(), ()>
	{
		let (packet, our_tcp_segment) = self.create_for_tcp_segment(transmission_control_block.remote_internet_protocol_address())?;
		self.send_empty(packet, our_tcp_segment, transmission_control_block, now, Flags::PushAcknowledgment, transmission_control_block.SND_UNA_less_one(), transmission_control_block.RCV_NXT(), None);
		Ok(())
	}
	
	#[inline(always)]
	pub(crate) fn send_challenge_acknowledgment(&self, packet: TCBA::Packet, transmission_control_block: &mut impl SendPacketTransmissionControlBlock<TCBA::Address>, now: MonotonicMillisecondTimestamp)
	{
		self.send_empty(packet, self.reuse_reversing_source_and_destination_addresses_for_tcp_segment(packet), transmission_control_block, now, Flags::Acknowledgment, transmission_control_block.SND_NXT(), transmission_control_block.RCV_NXT(), None);
	}
	
	#[inline(always)]
	pub(crate) fn send_reset_without_packet_to_reuse(&self, transmission_control_block: &mut impl SendPacketTransmissionControlBlock<TCBA::Address>, now: MonotonicMillisecondTimestamp, SEQ: WrappingSequenceNumber) -> Result<(), ()>
	{
		let (packet, our_tcp_segment) = self.create_for_tcp_segment(transmission_control_block.remote_internet_protocol_address())?;
		self.send_reset_common(packet, our_tcp_segment, transmission_control_block, now, SEQ);
		Ok(())
	}
	
	#[inline(always)]
	pub(crate) fn send_zero_window_probe(&self, transmission_control_block: &mut impl SendPacketTransmissionControlBlock<TCBA::Address>, now: MonotonicMillisecondTimestamp) -> Result<(), ()>
	{
		struct ZeroWindowProbePayloadWriter;
		
		impl PayloadWriter for ZeroWindowProbePayloadWriter
		{
			#[inline(always)]
			fn write(&self, segment_payload_starts_at_pointer: NonNull<u8>, _maximum_payload_size_unless_a_zero_window_probe: u32) -> usize
			{
				const GarbageByteCount: usize = 1;
				
				segment_payload_starts_at_pointer.as_ptr().write_bytes(0x00, GarbageByteCount);
				
				GarbageByteCount
			}
		}
		
		debug_assert!(transmission_control_block.send_window_is_zero(), "SND.WND is not zero");
		
		let (packet, our_tcp_segment) = self.create_for_tcp_segment(transmission_control_block.remote_internet_protocol_address())?;
		self.send(packet, our_tcp_segment, transmission_control_block, now, Flags::AcknowledgmentPush, transmission_control_block.SND_NXT(), transmission_control_block.RCV_NXT(), None, ZeroWindowProbePayloadWriter);
		Ok(())
	}
	
	pub(crate) fn send_data(&self, buffer: &[u8], transmission_control_block: &mut impl SendPacketTransmissionControlBlock<TCBA::Address>, now: MonotonicMillisecondTimestamp) -> Result<usize, ()>
	{
		struct DataPayloadWriter(buffer);
		
		impl PayloadWriter for DataPayloadWriter
		{
			#[inline(always)]
			fn write(&self, segment_payload_starts_at_pointer: NonNull<u8>, maximum_payload_size_unless_a_zero_window_probe: u32) -> usize
			{
				let maximum_payload_size_unless_a_zero_window_probe = maximum_payload_size_unless_a_zero_window_probe as usize;
				if (maximum_payload_size_unless_a_zero_window_probe) > self.0.len()
				{
					self.0.len()
				}
				else
				{
					maximum_payload_size_unless_a_zero_window_probe
				}
			}
		}
		
		debug_assert!(transmission_control_block.send_window_is_not_zero(), "SND.WND is zero");
		
		let (packet, our_tcp_segment) = self.create_for_tcp_segment(transmission_control_block.remote_internet_protocol_address())?;
		self.send(packet, our_tcp_segment, transmission_control_block, now, Flags::Acknowledgment, transmission_control_block.SND_NXT(), transmission_control_block.RCV_NXT(), None, DataPayloadWriter(buffer));
		Ok(XXXX)
		// TODO: Return how many bytes were put into the segment. Code needs to keep buffer pointer.
	}
	
	#[inline(always)]
	pub(crate) fn send_reset(&self, packet: TCBA::Packet, transmission_control_block: &mut impl SendPacketTransmissionControlBlock<TCBA::Address>, now: MonotonicMillisecondTimestamp, SEQ: WrappingSequenceNumber)
	{
		self.send_reset_common(packet, self.reuse_reversing_source_and_destination_addresses_for_tcp_segment(packet), transmission_control_block, now, SEQ)
	}
	
	#[inline(always)]
	fn send_reset_common(&self, packet: TCBA::Packet, our_tcp_segment: &mut TcpSegment, transmission_control_block: &mut impl SendPacketTransmissionControlBlock<TCBA::Address>, now: MonotonicMillisecondTimestamp, SEQ: WrappingSequenceNumber)
	{
		// Strictly speaking, it is valid to send a Reset before establishing synchronized state, but it is nearly always a security vulnerability.
		transmission_control_block.debug_assert_action_is_only_valid_in_synchronized_states();
		
		self.send_empty(packet, our_tcp_segment, transmission_control_block, now, Flags::Reset, SEQ, transmission_control_block.RCV_NXT(), None);
	}
	
	#[inline(always)]
	fn send_empty(&self, packet: TCBA::Packet, our_tcp_segment: &mut TcpSegment, transmission_control_block: &mut impl SendPacketTransmissionControlBlock<TCBA::Address>, now: MonotonicMillisecondTimestamp, flags: Flags, SEQ: WrappingSequenceNumber, ACK: WrappingSequenceNumber, selective_acknowledgment_block: Option<SelectiveAcknowledgmentBlock>)
	{
		struct EmptyPayloadWriter;
		
		impl PayloadWriter for EmptyPayloadWriter
		{
			#[inline(always)]
			fn write(&self, _segment_payload_starts_at_pointer: NonNull<u8>, _maximum_payload_size_unless_a_zero_window_probe: u32) -> usize
			{
				0
			}
		}
		
		self.send(packet, our_tcp_segment, transmission_control_block, now, flags, SEQ, ACK, selective_acknowledgment_block, EmptyPayloadWriter);
	}
	
	fn send(&self, packet: TCBA::Packet, our_tcp_segment: &mut TcpSegment, transmission_control_block: &mut impl SendPacketTransmissionControlBlock<TCBA::Address>, now: MonotonicMillisecondTimestamp, mut flags: Flags, SEQ: WrappingSequenceNumber, ACK: WrappingSequenceNumber, selective_acknowledgment_block: Option<SelectiveAcknowledgmentBlock>, payload_writer: impl PayloadWriter) -> usize
	{
		let start_of_options_data_pointer = our_tcp_segment.options_data_pointer();
		
		let md5_authentication_key = transmission_control_block.md5_authentication_key();
		
		let (end_of_options_data_pointer, previously_reserved_space_options_data_pointer) =
		{
			let mut options_data_pointer = start_of_options_data_pointer;
			
			options_data_pointer = transmission_control_block.write_timestamping_option(options_data_pointer, now);
			
			let (mut options_data_pointer, previously_reserved_space_options_data_pointer) = Self::reserve_space_for_m5_option(options_data_pointer, md5_authentication_key);
			
			if let Some(selective_acknowledgment_block) = selective_acknowledgment_block
			{
				options_data_pointer = TcpSegment::write_selective_acknowledgments_option(options_data_pointer, selective_acknowledgment_block)
			}
			
			(options_data_pointer, previously_reserved_space_options_data_pointer)
		};
		
		let padded_options_size = TcpSegment::round_up_options_size_to_multiple_of_four_and_set_padding_to_zero(start_of_options_data_pointer, end_of_options_data_pointer);
		
		let SND_NXT_old = transmission_control_block.SND_NXT();
		let maximum_payload_size = transmission_control_block.maximum_payload_size_excluding_synchronize_and_finish();
		let payload_size = payload_writer(unsafe { NonNull::new_unchecked(start_of_options_data_pointer + padded_options_size) }, maximum_payload_size);
		transmission_control_block.increment_SND_NXT(payload_size as u32);
		
		let layer_4_packet_size = TcpSegment::layer_4_packet_size(padded_options_size, payload_size);
		
		let is_a_zero_window_probe = (payload_size == 1 && transmission_control_block.send_window_is_zero() && SEQ == SND_NXT_old);
		let is_a_retransmission = false; // we'll handle this specially.
		
		let is_a_data_payload_and_is_its_first_transmission = payload_size != 0 && !is_a_zero_window_probe && !is_a_retransmission;
		
		if is_a_data_payload_and_is_its_first_transmission
		{
			transmission_control_block.bytes_sent_in_payload_in_a_segment_which_is_not_a_zero_window_probe_or_retransmission(payload_size);
			
			if let Some(explicit_congestion_notification_state) = transmission_control_block.explicit_congestion_notification_state_mutable_reference()
			{
				if transmission_control_block.is_state_synchronized()
				{
					// Only set the ECT(0) code point for explicit congestion notification if:-
					//
					// * We negotiated ECN;
					// * The connection state is synchronized (ie has reached Established or later);
					// * We are sending a data packet (payload_size != 0);
					//   * which is not a zero window probe (RFC 3168 Section 6.1.6);
					// * We are not re-transmitting a packet.
					packet.set_explicit_congestion_notification_state_ect_0();
					
					// RFC 3168 Section 6.1.2 Page 19 Paragraph 2: "... the CWR bit in the TCP header SHOULD NOT be set on retransmitted packets".
					//
					// RFC 3168 Section 6.1.2 Page 19 Paragraph 3: "When the TCP data sender is ready to set the CWR bit after reducing the congestion window, it SHOULD set the CWR bit only on the first new data packet that it transmits".
					if explicit_congestion_notification_state.set_congestion_window_reduced_on_first_new_data_packet_and_turn_off_signalling()
					{
						flags |= Flags::CongestionWindowReduced;
					}
				}
			}
		}
		
		let space_available_for_writing_payload = transmission_control_block.maximum_segment_payload_size(padded_options_size) - packet.internet_protocol_options_or_extension_headers_additional_overhead();
		
		{
			our_tcp_segment.set_for_send(transmission_control_block.remote_port_local_port(), SEQ, ACK, padded_options_size, flags, transmission_control_block.receive_segment_window_size());
			
			self.check_sum_layering.calculate_in_software_and_set_if_required(our_tcp_segment, layer_4_packet_size, &self.local_internet_protocol_address, transmission_control_block.remote_internet_protocol_address());
		}
		
		if let Some(md5_authentication_key) = md5_authentication_key
		{
			md5_authentication_key.deref().write_md5_option_into_previously_reserved_space(&self.local_internet_protocol_address, transmission_control_block.remote_internet_protocol_address(), padded_options_size, payload_size, our_tcp_segment, previously_reserved_space_options_data_pointer);
		}
		
		packet.set_layer_4_payload_length(layer_4_packet_size);
		
		self.send_packet(packet);
		
		payload_size
	}
	
	#[inline(always)]
	fn send_packet(&self, packet: TCBA::Packet)
	{
		self.transmission_control_block_abstractions.enqueue_packet_transmitting_if_full(packet);
	}
	
	#[inline(always)]
	fn create_for_tcp_segment<'a>(&self, remote_internet_protocol_address: &TCBA::Address) -> Result<(TCBA::Packet, &'a mut TcpSegment), ()>
	{
		self.transmission_control_block_abstractions.create_packet(&self.local_internet_protocol_address, remote_internet_protocol_address, Self::Layer4ProtocolNumber::Tcp).map(|(packet, pointer_to_tcp_segment)| (packet, unsafe { &mut * (pointer_to_tcp_segment.as_ptr() as *mut TcpSegment) }))
	}
	
	#[inline(always)]
	fn reuse_reversing_source_and_destination_addresses_for_tcp_segment<'a>(&self, packet: TCBA::Packet) -> &'a mut TcpSegment
	{
		let pointer_to_tcp_segment = self.transmission_control_block_abstractions.reuse_packet_reversing_source_and_destination_addresses(Self::Layer4ProtocolNumber::Tcp, packet);
		
		unsafe { &mut * (pointer_to_tcp_segment.as_ptr() as *mut TcpSegment) }
	}
}
