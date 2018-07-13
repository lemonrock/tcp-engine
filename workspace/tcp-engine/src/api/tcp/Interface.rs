// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Represents an interface to an ethernet device.
pub struct Interface<TCBA: TransmissionControlBlockAbstractions>
{
	transmission_control_block_abstractions: TCBA,
	check_sum_layering: CheckSumLayering,
	listening_server_port_combination_validity: PortCombinationValidity,
	local_internet_protocol_address: TCBA::Address,
	transmission_control_blocks: RefCell<BoundedHashMap<TransmissionControlBlockKey<TCBA::Address>, TransmissionControlBlock<TCBA>>>,
	transmission_control_blocks_send_buffers: Rc<MagicRingBuffersArena>,
	recently_closed_outbound_client_connection_source_ports: RefCell<LeastRecentlyUsedCacheWithExpiry<(TCBA::Address, u16), PortBitSet>>,
	recent_connections_congestion_data: RefCell<LeastRecentlyUsedCacheWithExpiry<TCBA::Address, CachedCongestionData>>,
	initial_sequence_number_generator: InitialSequenceNumberGenerator,
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
	pub fn new(transmission_control_block_abstractions: TCBA, check_sum_layering: CheckSumLayering, listening_server_port_combination_validity: PortCombinationValidity, local_internet_protocol_address: TCBA::Address, transmission_control_blocks_map_capacity: usize, maximum_recently_closed_outbound_client_connections_source_ports: usize, maximum_recent_connections_capacity: usize, expiry_period: MillisecondDuration, authentication_pre_shared_secret_keys: AuthenticationPreSharedSecretKeys) -> Self
	{
		const OutboundConnectionExpiryPeriodIsRfc793DoubleMaximumSegmentLifetime: MillisecondDuration = MillisecondDuration::TwoMinutes * 2;
		
		const SendBufferSize: usize = 256 * 1024;
		
		let now = Tick::now();
		
		Self
		{
			transmission_control_block_abstractions,
			check_sum_layering,
			listening_server_port_combination_validity,
			local_internet_protocol_address,
			transmission_control_blocks: RefCell::new(BoundedHashMap::new(transmission_control_blocks_map_capacity)),
			transmission_control_blocks_send_buffers: MagicRingBuffersArena::new(transmission_control_blocks_map_capacity, SendBufferSize),
			recently_closed_outbound_client_connection_source_ports: RefCell::new(LeastRecentlyUsedCacheWithExpiry::new(maximum_recently_closed_outbound_client_connections_source_ports, OutboundConnectionExpiryPeriodIsRfc793DoubleMaximumSegmentLifetime)),
			recent_connections_congestion_data: RefCell::new(LeastRecentlyUsedCacheWithExpiry::new(maximum_recent_connections_capacity, expiry_period)),
			initial_sequence_number_generator: InitialSequenceNumberGenerator::default(),
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
	
	/// NOTE: RFC 2675 IPv6 jumbograms are not supported.
	///
	/// This logic DOES NOT validate:-
	///
	/// * that source and destination addreses are permitted, eg are not multicast (this is the responsibility of lower layers);
	/// * that the source and destination addresses (and ports) are not the same.
	///
	/// `layer_4_packet_size` is NOT the same as the IPv6 payload size; in this case, it is the IPv6 payload size LESS the extensions headers size.
	#[inline(always)]
	pub fn incoming_segment(&self, now: MonotonicMillisecondTimestamp, packet: TCBA::Packet, layer_4_packet_size: usize)
	{
		// Validates:-
		//
		// * That the `tcp_segment_offset` is within the packet (debug only).
		// * That the TCP fixed header (ie the frame excluding options) can fit inside the packet.
		// * That the TCP header length valid is valid.
		// * That the TCP header (fixed and options) can fit inside the packet.
		macro_rules! tcp_segment_of_valid_length
		{
			($self: ident, $packet: ident, $tcp_segment_length: ident) =>
			{
				{
					let tcp_segment_offset = $packet.layer_4_packet_offset::<TCBA::Address>();
					
					if unlikely(tcp_segment_length < size_of::<TcpFixedHeader>())
					{
						drop!($self, $packet, "TCP frame (segment) is shorted than minimum size of TCP fixed header (excluding options)")
					}
					
					let tcp_segment = $packet.offset_into_data_reference::<TcpSegment>($tcp_segment_offset);
					
					let raw_data_length_bytes = tcp_segment.raw_data_length_bytes();
					
					if unlikely(raw_data_length_bytes < (5 << 4))
					{
						drop!($self, $packet, "TCP header length 32-bit words was too small (less than 5)")
					}
					
					let header_length_in_bytes_including_options = raw_data_length_bytes as usize;
					
					if unlikely(tcp_segment_length < header_length_in_bytes_including_options)
					{
						drop!($self, $packet, "TCP frame (segment) length is less than that indicated by its own header length, ie the TCP frame is cut short")
					}
					
					let options_length = header_length_in_bytes_including_options - size_of::<TcpFixedHeader>();
					
					(tcp_segment, tcp_segment_length, options_length)
				}
			}
		}
		
		macro_rules! finish_parsing_of_tcp_segment
		{
			($self: ident, $now: ident, $packet: ident, $smallest_acceptable_tcp_maximum_segment_size_option: ident, $options_length: ident, $all_flags: ident, $source_internet_protocol_address: ident, $SEG: ident, $tcp_segment_length: ident) =>
			{
				{
					let options_data_pointer = $SEG.options_data_pointer();
					let tcp_options = parse_options!($self, $packet, $smallest_acceptable_tcp_maximum_segment_size_option, options_data_pointer, $options_length, $all_flags);
					ParsedTcpSegment::new($now, $packet, $self, $source_internet_protocol_address, $SEG, tcp_options, $options_length, $tcp_segment_length)
				}
			}
		}
		
		macro_rules! validate_connection_establishment_segment
		{
			($self: ident, $now: ident, $packet: ident, $smallest_acceptable_tcp_maximum_segment_size_option: ident, $options_length: ident, $all_flags: ident, $source_internet_protocol_address: ident, $SEG: ident, $tcp_segment_length: ident) =>
			{
				{
					if $self.listening_server_port_combination_validity.port_combination_is_invalid($SEG.source_port_destination_port())
					{
						drop!($self, $packet, "TCP connection establishment segment (Synchronize or Acknowledgment) is not from an acceptable combination of source (remote) port and destination (local) port")
					}
					
					finish_parsing_of_tcp_segment!($self, $now, $packet, $smallest_acceptable_tcp_maximum_segment_size_option, $options_length, $all_flags, $source_internet_protocol_address, $SEG, $tcp_segment_length)
				}
			}
		}
		
		macro_rules! received_synchronize_when_state_is_listen_or_synchronize_received
		{
			($self: ident, $now: ident, $packet: ident, $smallest_acceptable_tcp_maximum_segment_size_option: ident, $options_length: ident, $all_flags: ident, $source_internet_protocol_address: ident, $SEG: ident, $tcp_segment_length: ident, $explicit_congestion_notification_supported: expr) =>
			{
				{
					// Implied from RFC 793 Section 3.7 Open Call CLOSED State page 54: "A SYN segment of the form <SEQ=ISS><CTL=SYN> is sent".
					if unlikely($SEG.ACK().is_not_zero())
					{
						drop!($self, $packet, "TCP Synchronize segment has a non-zero initial ACK field")
					}
					
					if cfg!(not(feature = "rfc-8311-permit-explicit-congenstion-markers-on-all-packets"))
					{
						// RFC 3168 Section 6.1.1: "A host MUST NOT set ECT on SYN or SYN-ACK packets".
						if unlikely($packet.explicit_congestion_notification().is_ect_or_congestion_experienced_set())
						{
							drop!($self, $packet, "TCP packet has an Internet Protocol Explicit Congestion Notification (ECN) set for a Synchronize segment in violation of RFC 3168")
						}
					}
					
					let mut parsed_tcp_segment = validate_connection_establishment_segment!($self, $now, $packet, $smallest_acceptable_tcp_maximum_segment_size_option, $options_length, $all_flags, $source_internet_protocol_address, $SEG, $tcp_segment_length);
					parsed_tcp_segment.received_synchronize_when_state_is_listen_or_synchronize_received($explicit_congestion_notification_supported)
				}
			}
		}
		
		macro_rules! received_acknowledgment_when_state_is_listen_or_synchronize_received
		{
			($self: ident, $now: ident, $packet: ident, $smallest_acceptable_tcp_maximum_segment_size_option: ident, $options_length: ident, $all_flags: ident, $source_internet_protocol_address: ident, $SEG: ident, $tcp_segment_length: ident) =>
			{
				{
					if unlikely($self.transmission_control_blocks_at_maximum_capacity())
					{
						drop!($self, $SEG, "TCP at maximum capacity")
					}
					
					let mut parsed_tcp_segment = validate_connection_establishment_segment!($self, $now, $packet, $smallest_acceptable_tcp_maximum_segment_size_option, $options_length, $all_flags, $source_internet_protocol_address, $SEG, $tcp_segment_length);
					parsed_tcp_segment.received_acknowledgment_when_state_is_listen_or_synchronize_received()
				}
			}
		}
		
		let tcp_segment_length = layer_4_packet_size;
		let (SEG, options_length) = tcp_segment_of_valid_length!(self, packet, tcp_segment_length);
		
		let all_flags = SEG.all_flags();
		
		if unlikely(all_flags.are_null())
		{
			drop!(packet, "TCP null scan")
		}
		
		// RFC 3360 Section 2.1: "... the Reserved field should be zero when sent and ignored when received, unless specified otherwise by future standards actions".
		//
		// We VIOLATE the RFC here.
		if unlikely(SEG.are_reserved_bits_set_or_has_historic_nonce_sum_flag())
		{
			// RFC 3360 Section 2.1: "... the phrasing in RFC 793 does not permit sending resets in response to TCP	packets with a non-zero Reserved field, as is explained in the section above".
			drop!(packet, "TCP reserved bits are set or have historic Nonce Sum (NS) flag set")
		}
		
		if unlikely(all_flags.has_urgent_flag())
		{
			drop!(packet, "TCP URG flag is not supported")
		}
		else if cfg!(feature = "drop-urgent-pointer-field-non-zero")
		{
			if unlikely(SEG.urgent_pointer_if_URG_flag_set_is_not_zero())
			{
				drop!(packet, "TCP drop-urgent-pointer-field-non-zero")
			}
		}
		
		let source_internet_protocol_address = packet.source_internet_protocol_address(internet_protocol_packet_offset);
		
		if unlikely(self.is_tcp_check_sum_invalid(SEG, layer_4_packet_size, source_internet_protocol_address))
		{
			drop!(packet, "TCP check sum is invalid")
		}
		
		let smallest_acceptable_tcp_maximum_segment_size_option = MaximumSegmentSizeOption(TCBA::Address::SmallestAcceptableMaximumSegmentSize);
		
		match self.find_transmission_control_block_for_incoming_segment(source_internet_protocol_address, SEG)
		{
			// State is either Listen or SynchronizeReceived
			None => match all_flags
			{
				Flags::Synchronize => received_synchronize_when_state_is_listen_or_synchronize_received!(self, now, packet, smallest_acceptable_tcp_maximum_segment_size_option, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length, false),
				
				Flags::SynchronizeExplicitCongestionEchoCongestionWindowReduced => received_synchronize_when_state_is_listen_or_synchronize_received!(self, now, packet, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length, true),
				
				Flags::Acknowledgment | Flags::AcknowledgmentPush => received_acknowledgment_when_state_is_listen_or_synchronize_received!(self, now, packet, smallest_acceptable_tcp_maximum_segment_size_option, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length),
				
				// "A Finite State Machine Model of TCP Connections in the Transport Layer", J. Treurniet and J. H. Lefebvre, 2003 (http://cradpdf.drdc-rddc.gc.ca/PDFS/unc25/p520460.pdf) pages 5 & 6:-
				// State that whilst these states are techically valid, they are probably a scan.
				//
				// We VIOLATE RFC 793 here; to send a Reset is to either reveal to a potential attacker that we exist OR to inadvertently abort because of a spoofed packet an existing connection.
				//
				// As such, rather than sending a Reset (which is technically the correct thing to do), we just drop the packet.
				Flags::FinishAcknowledgment | Flags::FinishAcknowledgmentPush | Flags::ResetAcknowledgment => drop!(packet, "TCP FinishAcknowledgment, FinishAcknowledgmentPush or ResetAcknowledgment segment when replying to a syncookie (ignored)"),
				
				// RFC 5961 Section 3.2 Page 8:-
				// "In all states except SYN-SENT, all reset (RST) packets are validated by checking their SEQ-fields [sequence numbers].
				// A reset is valid if its sequence number exactly matches the next expected sequence number.
				// If the RST arrives and its sequence number field does NOT match the next expected sequence number but is within the window, then the receiver should generate an ACK \*.
				// In all other cases, where the SEQ-field does not match and is outside the window, the receiver MUST silently discard the segment."
				//
				// \* This is known as a 'Challenge ACK'.
				//
				// We VIOLATE RFC 5961 here and do not send a 'Challenge ACK' under any circumstances: to do so would be to reveal that a syncookie we sent as an initial challenge is INVALID.
				Flags::Reset => drop!(packet, "TCP Reset segment when replying to a syncookie (ignored)"),
				
				_ => drop!(packet, "TCP segment contained a combination of flags invalid for replying to a syncookie"),
			}
			
			Some(transmission_control_block) =>
			{
				let mut parsed_tcp_segment = finish_parsing_of_tcp_segment!(self, now, packet, smallest_acceptable_tcp_maximum_segment_size_option, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length);
				parsed_tcp_segment.process_tcp_segment_when_state_is_other_than_listen_or_synchronize_received(transmission_control_block.deref())
			}
		}
	}
}

/// Incoming segments.
impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	#[inline(always)]
	pub(crate) fn validate_syncookie(&self, remote_internet_protocol_address: &TCBA::Address, SEG: &ParsedTcpSegment) -> Result<ParsedSynCookie, ()>
	{
		self.syn_cookie_protection.validate_syncookie_in_acknowledgment(&self.local_internet_protocol_address, remote_internet_protocol_address, SEG)
	}
	
	#[inline(always)]
	fn is_tcp_check_sum_invalid(&self, SEG: &TcpSegment, layer_4_packet_size: usize, remote_internet_protocol_address: &TCBA::Address) -> bool
	{
		self.check_sum_layering.is_tcp_check_sum_invalid(SEG, layer_4_packet_size, remote_internet_protocol_address, &self.local_internet_protocol_address)
	}
	
	#[inline(always)]
	fn dropped_packet_explanation(&self, explanation: &'static str)
	{
		if cfg!(debug_assertions)
		{
			eprintln!("Dropped packet '{}'", explanation)
		}
	}
}

/// Transmission control blocks.
impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	#[inline(always)]
	pub(crate) fn new_transmission_control_block_for_outgoing_client_connection(&self, remote_internet_protocol_address: TCBA::Address, remote_port: u16, now: MonotonicMillisecondTimestamp, explicit_congestion_notification_supported: bool, connection_time_out: MillisecondDuration) -> Result<(), ()>
	{
		if self.transmission_control_blocks_at_maximum_capacity()
		{
			return Err(())
		}
		
		let local_port = self.pick_a_source_port_for_a_new_outgoing_connection(&remote_internet_protocol_address, remote_port)?;
		
		let remote_port_local_port = RemotePortLocalPort::from_remote_port_local_port(NetworkEndianU16::from_native_endian(remote_port), NetworkEndianU16::from_native_endian(local_port));
		
		let (packet, our_tcp_segment) = self.create_for_tcp_segment(&remote_internet_protocol_address)?;
		
		let ISS = interface.generate_initial_sequence_number(now, &remote_internet_protocol_address, remote_port_local_port);
		
		let transmission_control_block = TransmissionControlBlock::new_for_closed_to_synchronize_sent(self, remote_internet_protocol_address, remote_port_local_port, now, ISS, explicit_congestion_notification_supported);
		
		let transmission_control_blocks = self.transmission_control_blocks.borrow_mut();
		let transmission_control_block = transmission_control_blocks.entry(transmission_control_block.key()).or_insert(transmission_control_block);
		
		self.send_synchronize(packet, our_tcp_segment, transmission_control_block, now);
		
		// TODO: schedule retrans timer, cancel in syn_sent_syn_ack_recd
		transmission_control_block.schedule_user_time_out_alarm_for_connection(connection_time_out);
		xxxx;
		
		Ok(())
	}
	
	#[inline(always)]
	fn pick_a_source_port_for_a_new_outgoing_connection(&self, remote_internet_protocol_address: &TCBA::Address, remote_port: u16) -> Result<u16, ()>
	{
		let mut recently_closed_client_connections = LeastRecentlyUsedCacheWithExpiry::new(maximum_capacity, OutboundConnectionExpiryPeriodIsRfc793DoubleMaximumSegmentLifetime);
		
		let valid_local_ports = &self.listening_server_port_combination_validity.valid_local_ports;
		
		// RFC 6056: Section 3.2: "... ephemeral port selection algorithms should use the whole range 1024-65535.
		// ...
		// port numbers that may be needed for providing a particular service at the local host SHOULD NOT be included in the pool of port numbers available for ephemeral port randomization".
		let recently_closed_client_connection_source_ports = self.recently_closed_outbound_client_connection_source_ports.borrow_mut();
		
		let key = (*remote_internet_protocol_address, remote_port);
		
		if let Some(port_bit_set) = recently_closed_client_connection_source_ports.get_mut(&key)
		{
			let source_port = match source_ports_port_bit_set.union(valid_local_ports).find_unused_securely_randomly(1024)
			{
				None => return Err(()),
				Some(source_port) => source_port,
			};
			
			source_ports_port_bit_set.insert(source_port);
			
			Ok(source_port)
		}
		else
		{
			let mut source_ports_port_bit_set = PortBitSet::new_with_rfc_6056_ephemeral_ports_available();
			
			let source_port = match source_ports_port_bit_set.union(valid_local_ports).find_unused_securely_randomly(1024)
			{
				None => return Err(()),
				Some(source_port) => source_port,
			};
			
			source_ports_port_bit_set.insert(source_port);
			
			recently_closed.insert(key, source_ports_port_bit_set);
			
			Ok(source_port)
		}
	}
	
	#[inline(always)]
	pub(crate) fn allocate_a_send_buffer(&self) -> MagicRingBuffer
	{
		MagicRingBuffersArena::allocate(&self.transmission_control_blocks_send_buffers)
	}
	
	#[inline(always)]
	pub(crate) fn new_transmission_control_block_for_incoming_segment(&self, transmission_control_block: TransmissionControlBlock<TCBA>)
	{
		let transmission_control_blocks = self.transmission_control_blocks.borrow_mut();
		let transmission_control_block = transmission_control_blocks.entry(transmission_control_block.key()).or_insert(transmission_control_block);
		
		
		// TODO: Schedule first alarm.
		x;
		let alarms = self.alarms();
		transmission_control_block.keep_alive_XXXXX(alarms);
	}
	
	#[inline(always)]
	pub(crate) fn destroy_transmission_control_block(&self, key: &TransmissionControlBlockKey<TCBA::Address>, now: MonotonicMillisecondTimestamp)
	{
		let transmission_control_block = self.transmission_control_blocks.borrow_mut().remove(key);
		
		self.update_recent_congestion_data(&transmission_control_block, now);
		transmission_control_block.destroying(self, interface.alarms())
	}
	
	#[inline(always)]
	fn transmission_control_blocks_at_maximum_capacity(&self) -> bool
	{
		let transmission_control_blocks = self.transmission_control_blocks.borrow();
		transmission_control_blocks.is_full()
	}
	
	#[inline(always)]
	fn find_transmission_control_block_for_incoming_segment<'a>(&'a self, remote_internet_protocol_address: &TCBA::Address, SEG: &TcpSegment) -> Option<Ref<'a, TransmissionControlBlock<TCBA>>>
	{
		#[inline(always)]
		fn smuggled_pointer_hack_because_ref_map_must_return_a_reference_not_an_option<'a, TCBA: TransmissionControlBlockAbstractions>() -> &'a TransmissionControlBlock<TCBA>
		{
			unsafe { &*NonNull::dangling().as_ptr() }
		}
		
		let key = TransmissionControlBlockKey::from_incoming_segment(remote_internet_protocol_address: Address, SEG: &TcpSegment);
		
		let transmission_control_blocks = self.transmission_control_blocks.borrow();
		
		let extant_value_or_smuggled_pointer_representing_none = Ref::map(transmission_control_blocks, |transmission_control_blocks| transmission_control_blocks.get(key).unwrap_or(smuggled_pointer_hack_because_ref_map_must_return_a_reference_not_an_option()));
		
		if (extant_value_or_smuggled_pointer_representing_none.deref() as *const _) == (smuggled_pointer_hack_because_ref_map_must_return_a_reference_not_an_option() as *const TransmissionControlBlock<TCBA>)
		{
			None
		}
		else
		{
			Some(extant_value_or_smuggled_pointer_representing_none)
		}
	}
	
	#[inline(always)]
	fn generate_initial_sequence_number(&self, remote_internet_protocol_address: &TCBA::Address, remote_port_local_port: RemotePortLocalPort)
	{
		self.initial_sequence_number_generator.generate_initial_sequence_number(self.local_internet_protocol_address, remote_internet_protocol_address, remote_port_local_port)
	}
}

/// Cached congestion data.
impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	#[inline(always)]
	pub(crate) fn cached_congestion_data<'a>(&self, now: MonotonicMillisecondTimestamp, remote_internet_protocol_address: &TCBA::Address) -> Ref<'a, CachedCongestionData>
	{
		static Default: CachedCongestionData = CachedCongestionData::Default;
		
		let recent_connections_congestion_data = self.recent_connections_congestion_data.borrow_mut();
		
		Ref::map(recent_connections_congestion_data, |recent_connections_congestion_data| recent_connections_congestion_data.get(key).unwrap_or(&Default))
	}
	
	#[inline(always)]
	fn update_recent_congestion_data(&self, transmission_control_block: &TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp)
	{
		let recent_connections_congestion_data = self.recent_connections_congestion_data.borrow_mut();
		
		let remote_internet_protocol_address = transmission_control_block.remote_internet_protocol_address();
		
		let (smoothed_round_trip_time, round_trip_time_variance) = transmission_control_block.smoothed_round_trip_time_and_round_trip_time_variance();
		if let Some(cached_connection_data) = recent_connections_congestion_data.get_mut(now, remote_internet_protocol_address)
		{
			cached_connection_data.update_retransmission_time_out(smoothed_round_trip_time_and_round_trip_time_variance);
		}
		else
		{
			recent_connections_congestion_data.insert(now, remote_internet_protocol_address, CachedCongestionData::new(smoothed_round_trip_time_and_round_trip_time_variance, transmission_control_block.congestion_control.ssthresh));
		}
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
	pub(crate) fn find_md5_authentication_key(&self, remote_internet_protocol_address: &Address, remote_port_local_port: RemotePortLocalPort) -> Option<&Rc<Md5PreSharedSecretKey>>
	{
		self.authentication_pre_shared_secret_keys.find_md5_authentication_key(remote_internet_protocol_address, remote_port_local_port.local_port())
	}
}

/// Miscellany.
impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	/// RFC 6691, Section 2: "When calculating the value to put in the TCP MSS option, the MTU value SHOULD be decreased by only the size of the fixed IP and TCP headers and SHOULD NOT be decreased to account for any possible IP or TCP options; conversely, the sender MUST reduce the TCP data length to account for any IP or TCP options that it is including in the packets that it sends.
	/// ... the goal is to avoid IP-level fragmentation of TCP packets".
	#[inline(always)]
	pub(crate) fn our_current_maximum_segment_size_without_fragmentation(&self, remote_internet_protocol_address: &TCBA::Address) -> u16
	{
		let path_maximum_transmission_unit = self.transmission_control_block_abstractions.current_path_maximum_transmission_unit(remote_internet_protocol_address);
		
		debug_assert!(path_maximum_transmission_unit >= TCBA::Address::MinimumPathMaximumTransmissionUnitSize, "path_maximum_transmission_unit '{}' is less than MinimumPathMaximumTransmissionUnitSize '{}'", path_maximum_transmission_unit, TCBA::Address::MinimumPathMaximumTransmissionUnitSize);
		
		let minimum_overhead_excluding_ip_options_ip_headers_and_tcp_options = TCBA::Address::SmallestLayer3HeaderSize + (size_of::<TcpFixedHeader>() as u16);
		
		debug_assert!(path_maximum_transmission_unit > minimum_overhead_excluding_ip_options_ip_headers_and_tcp_options, "path_maximum_transmission_unit '{}' is equal to or less than packet_headers_length_excluding_tcp_options '{}'", path_maximum_transmission_unit, minimum_overhead_excluding_ip_options_ip_headers_and_tcp_options);
		path_maximum_transmission_unit - minimum_overhead_excluding_ip_options_ip_headers_and_tcp_options
	}
}

/// Sending.
impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	fn send_synchronize(&self, packet: TCBA::Packet, our_tcp_segment: &mut TcpSegment, transmission_control_block: &TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp)
	{
		let remote_internet_protocol_address = transmission_control_block.remote_internet_protocol_address();
		let explicit_congestion_notification_supported = transmission_control_block.explicit_congestion_notification_supported();
		let md5_authentication_key = transmission_control_block.md5_authentication_key();
		
		let start_of_options_data_pointer = our_tcp_segment.options_data_pointer();
		
		let (end_of_options_data_pointer, previously_reserved_space_options_data_pointer) =
		{
			let mut options_data_pointer = start_of_options_data_pointer;
			let mut previously_reserved_space_options_data_pointer = 0;
			
			options_data_pointer = TcpSegment::write_maximum_segment_size_option(transmission_control_block.our_offered_maximum_segment_size_when_initiating_connections());
			
			options_data_pointer = TcpSegment::write_window_scale_option(InitialWindowSize::Scale);
			
			options_data_pointer = TcpSegment::write_selective_acknowledgment_permitted_option(options_data_pointer);
			
			options_data_pointer = TcpSegment::write_timestamps_option(options_data_pointer, transmission_control_block.normal_timestamps_option());
			
			if md5_authentication_key.is_some()
			{
				previously_reserved_space_options_data_pointer = options_data_pointer;
				options_data_pointer = TcpSegment::reserve_space_for_md5_option(options_data_pointer)
			}
			
			(options_data_pointer, previously_reserved_space_options_data_pointer)
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
			
			let ISS = transmission_control_block.SND.UNA();
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
			
			options_data_pointer = TcpSegment::write_maximum_segment_size_option(MaximumSegmentSizeOption::maximum_segment_size_to_send_to_remote(their_maximum_segment_size, self, remote_internet_protocol_address));
			
			if likely(their_window_scale.is_some())
			{
				options_data_pointer = TcpSegment::write_window_scale_option(InitialWindowSize::Scale)
			}
			
			if likely(their_selective_acknowledgment_permitted)
			{
				options_data_pointer = TcpSegment::write_selective_acknowledgment_permitted_option(options_data_pointer)
			}
			
			if let Some(their_timestamp) = their_timestamp
			{
				options_data_pointer = TcpSegment::write_timestamps_option(options_data_pointer, Timestamping::synflood_synchronize_acknowledgment_timestamps_option(their_timestamp.TSval))
			}
			
			if md5_authentication_key.is_some()
			{
				previously_reserved_space_options_data_pointer = options_data_pointer;
				options_data_pointer = TcpSegment::reserve_space_for_md5_option(options_data_pointer)
			}
			
			(options_data_pointer, previously_reserved_space_options_data_pointer)
		};
		
		let (padded_options_size, layer_4_packet_size) = TcpSegment::round_up_options_size_to_multiple_of_four_and_set_padding_to_zero(start_of_options_data_pointer, end_of_options_data_pointer);
		
		// TODO: Any payload writes (only if we use TCP fast-open).
		let payload_size = 0;
		
		let layer_4_packet_size = TcpSegment::layer_4_packet_size(padded_options_size, payload_size);
		
		{
			let syncookie = self.syn_cookie_protection.create_syn_cookie_for_synchronize_acnowledgment(now, &self.local_internet_protocol_address, remote_internet_protocol_address, SEG, their_maximum_segment_size, their_window_scale, their_selective_acknowledgment_permitted, explicit_congestion_notification_supported);
			
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
	pub(crate) fn send_final_acknowledgment_of_three_way_handshake(&self, packet: TCBA::Packet, transmission_control_block: &mut TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp, mut flags: Flags, SEQ: WrappingSequenceNumber, ACK: WrappingSequenceNumber)
	{
		transmission_control_block.update_Last_ACK_sent(ACK);
		self.send_empty(packet, self.reuse_reversing_source_and_destination_addresses_for_tcp_segment(packet), transmission_control_block, now, flags, SEQ, ACK, None);
	}
	
	#[inline(always)]
	pub(crate) fn send_acknowledgment(&self, packet: TCBA::Packet, transmission_control_block: &mut TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp, flags: Flags, SEQ: WrappingSequenceNumber, ACK: WrappingSequenceNumber)
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
	pub(crate) fn send_keep_alive_probe_without_packet_to_reuse(&self, transmission_control_block: &TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp) -> Result<(), ()>
	{
		let (packet, our_tcp_segment) = self.create_for_tcp_segment(transmission_control_block.remote_internet_protocol_address())?;
		self.send_empty(packet, our_tcp_segment, transmission_control_block, now, Flags::PushAcknowledgment, transmission_control_block.SND.UNA_less_one(), transmission_control_block.RCV.NXT(), None);
		Ok(())
	}
	
	#[inline(always)]
	pub(crate) fn send_challenge_acknowledgment(&self, packet: TCBA::Packet, transmission_control_block: &TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp)
	{
		self.send_empty(packet, self.reuse_reversing_source_and_destination_addresses_for_tcp_segment(packet), transmission_control_block, now, Flags::Acknowledgment, transmission_control_block.SND.NXT, transmission_control_block.RCV.NXT(), None);
	}
	
	#[inline(always)]
	pub(crate) fn send_reset_without_packet_to_reuse(&self, transmission_control_block: &TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp, SEQ: WrappingSequenceNumber) -> Result<(), ()>
	{
		let (packet, our_tcp_segment) = self.create_for_tcp_segment(transmission_control_block.remote_internet_protocol_address())?;
		self.send_reset_common(packet, our_tcp_segment, transmission_control_block, now, SEQ);
		Ok(())
	}
	
	#[inline(always)]
	pub(crate) fn send_zero_window_probe(&self, transmission_control_block: &TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp) -> Result<(), ()>
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
		
		let SND = &transmission_control_block.SND;
		debug_assert!(SND.window_is_zero(), "SND.WND is not zero");
		
		let (packet, our_tcp_segment) = self.create_for_tcp_segment(transmission_control_block.remote_internet_protocol_address())?;
		self.send(packet, our_tcp_segment, transmission_control_block, now, Flags::AcknowledgmentPush, SND.NXT, transmission_control_block.RCV.NXT(), None, ZeroWindowProbePayloadWriter);
		Ok(())
	}
	
	pub(crate) fn send_data(&self, buffer: &[u8], transmission_control_block: &TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp) -> Result<usize, ()>
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
		
		let SND = &transmission_control_block.SND;
		debug_assert!(SND.window_is_not_zero(), "SND.WND is zero");
		
		let (packet, our_tcp_segment) = self.create_for_tcp_segment(transmission_control_block.remote_internet_protocol_address())?;
		self.send(packet, our_tcp_segment, transmission_control_block, now, Flags::Acknowledgment, SND.NXT, transmission_control_block.RCV.NXT(), None, DataPayloadWriter(buffer));
		Ok(XXXX)
		// TODO: Return how many bytes were put into the segment. Code needs to keep buffer pointer.
	}
	
	#[inline(always)]
	pub(crate) fn send_reset(&self, packet: TCBA::Packet, transmission_control_block: &TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp, SEQ: WrappingSequenceNumber)
	{
		self.send_reset_common(packet, self.reuse_reversing_source_and_destination_addresses_for_tcp_segment(packet), transmission_control_block, now, SEQ)
	}
	
	#[inline(always)]
	fn send_reset_common(&self, packet: TCBA::Packet, our_tcp_segment: &mut TcpSegment, transmission_control_block: &TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp, SEQ: WrappingSequenceNumber)
	{
		debug_assert!(transmission_control_block.is_state_synchronized(), "We do not support sending Reset segments before the state has become Established");
		
		self.send_empty(packet, our_tcp_segment, transmission_control_block, now, Flags::Reset, SEQ, transmission_control_block.RCV.NXT(), None);
	}
	
	#[inline(always)]
	fn send_empty(&self, packet: TCBA::Packet, our_tcp_segment: &mut TcpSegment, transmission_control_block: &TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp, flags: Flags, SEQ: WrappingSequenceNumber, ACK: WrappingSequenceNumber, selective_acknowledgment_block: Option<SelectiveAcknowledgmentBlock>)
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
	
	fn send(&self, packet: TCBA::Packet, our_tcp_segment: &mut TcpSegment, transmission_control_block: &TransmissionControlBlock<TCBA>, now: MonotonicMillisecondTimestamp, mut flags: Flags, SEQ: WrappingSequenceNumber, ACK: WrappingSequenceNumber, selective_acknowledgment_block: Option<SelectiveAcknowledgmentBlock>, payload_writer: impl PayloadWriter) -> usize
	{
		let start_of_options_data_pointer = our_tcp_segment.options_data_pointer();
		
		let md5_authentication_key = transmission_control_block.md5_authentication_key();
		
		let (end_of_options_data_pointer, previously_reserved_space_options_data_pointer) =
		{
			let mut options_data_pointer = start_of_options_data_pointer;
			
			if let Some(timestamping) = transmission_control_block.timestamping_reference()
			{
				options_data_pointer = TcpSegment::write_timestamps_option(options_data_pointer, timestamping.normal_timestamps_option())
			}
			
			if md5_authentication_key.is_some()
			{
				previously_reserved_space_options_data_pointer = options_data_pointer;
				options_data_pointer = TcpSegment::reserve_space_for_md5_option(options_data_pointer)
			}
			
			if let Some(selective_acknowledgment_block) = selective_acknowledgment_block
			{
				options_data_pointer = TcpSegment::write_selective_acknowledgments_option(options_data_pointer, selective_acknowledgment_block)
			}
			
			(options_data_pointer, previously_reserved_space_options_data_pointer)
		};
		
		let padded_options_size = TcpSegment::round_up_options_size_to_multiple_of_four_and_set_padding_to_zero(start_of_options_data_pointer, end_of_options_data_pointer);
		
		let SND_NXT_old = transmission_control_block.SND.NXT;
		let maximum_payload_size = transmission_control_block.maximum_payload_size_excluding_synchronize_and_finish();
		let payload_size = payload_writer(unsafe { NonNull::new_unchecked(start_of_options_data_pointer + padded_options_size) }, maximum_payload_size);
		transmission_control_block.SND.NXT += payload_size;
		
		let layer_4_packet_size = TcpSegment::layer_4_packet_size(padded_options_size, payload_size);
		
		let is_a_zero_window_probe = (payload_size == 1 && transmission_control_block.SND.window_is_zero() && SEQ == SND_NXT_old);
		let is_a_retransmission = false; // we'll handle this specially.
		
		let is_a_data_payload_and_is_its_first_transmission = payload_size != 0 && !is_a_zero_window_probe && !is_a_retransmission;
		
		if is_a_data_payload_and_is_its_first_transmission
		{
			transmission_control_block.bytes_sent_in_payload_in_a_segment_which_is_not_a_zero_window_probe_or_retransmission(payload_size);
			
			if let Some(explicit_congestion_notification_state) = transmission_control_block.explicit_congestion_notification_state()
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
		
		let space_available_for_writing_payload = transmission_control_block.maximum_segment_size_to_send_to_remote - packet.internet_protocol_options_or_extension_headers_additional_overhead() - padded_options_size;
		
		{
			our_tcp_segment.set_for_send(transmission_control_block.remote_port_local_port(), SEQ, ACK, padded_options_size, flags, transmission_control_block.RCV.segment_window_size());
			
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
