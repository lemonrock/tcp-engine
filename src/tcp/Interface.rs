// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Represents an interface to an ethernet device.
pub struct Interface<TCBA: TransmissionControlBlockAbstractions>
{
	transmission_control_block_abstractions: TCBA,
	check_sum_layering: CheckSumLayering,
	listening_server_port_combination_validity: PortCombinationValidity,
	local_internet_protocol_address: A,
	transmission_control_blocks: RefCell<HashMap<TransmissionControlBlockKey<TCBA::Address>, TransmissionControlBlock<TCBA>>>,
	initial_sequence_number_generator: IntitialSequenceNumberGenerator,
	syn_cookie_protection: SynCookieProtection,
	alarms: Alarms<TCBA>,
}

impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	/// Creates a new instance.
	#[inline(always)]
	pub fn new(transmission_control_block_abstractions: TCBA, check_sum_layering: CheckSumLayering, listening_server_port_combination_validity: PortCombinationValidity, local_internet_protocol_address: TCBA::Address, transmission_control_blocks_map_capacity: u32) -> Self
	{
		let now = Tick::now();
		
		Self
		{
			transmission_control_block_abstractions,
			check_sum_layering,
			listening_server_port_combination_validity,
			local_internet_protocol_address,
			transmission_control_blocks: RefCell::new(HashMap::with_capacity(transmission_control_blocks_map_capacity as usize)),
			initial_sequence_number_generator: IntitialSequenceNumberGenerator::default(),
			syn_cookie_protection: SynCookieProtection::new(now),
			alarms: Alarms::new(now),
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
	/// `layer_4_packet_size` is NOT the same as the IPv6 payload size; in this case, it is the IPv6 payload size LESS the extensions headers size.
	#[inline(always)]
	pub fn incoming_segment(&self, now: MonotonicMillisecondTimestamp, packet: TCBA::Packet, tcp_segment_offset: usize, layer_4_packet_size: usize)
	{
		// Validates:-
		//
		// * That the `tcp_segment_offset` is within the packet (debug only).
		// * That the TCP fixed header (ie the frame excluding options) can fit inside the packet.
		// * That the TCP header length valid is valid.
		// * That the TCP header (fixed and options) can fit inside the packet.
		macro_rules! tcp_segment_of_valid_length
		{
			($packet: ident, $tcp_segment_offset: ident) =>
			{
				{
					let tcp_segment_length =
					{
						let packet_length = $packet.packet_length();
						debug_assert!($tcp_segment_offset <= packet_length, "tcp_segment_offset {} exceeds packet_length {}", $tcp_segment_offset, packet_length);
						packet_length - $tcp_segment_offset
					};
					
					if unlikely(tcp_segment_length < size_of::<TcpFixedHeader>())
					{
						drop!($packet, "TCP frame (segment) is shorted than minimum size of TCP fixed header (excluding options)")
					}
					
					let tcp_segment: &TcpSegment = unsafe { &* $packet.offset_into_data($tcp_segment_offset).as_ptr() };
					
					let raw_data_length_bytes = tcp_segment.raw_data_length_bytes();
					
					if unlikely(raw_data_length_bytes < (5 << 4))
					{
						drop!($packet, "TCP header length 32-bit words was too small (less than 5)")
					}
					
					let header_length_in_bytes_including_options = raw_data_length_bytes as usize;
					
					if unlikely(tcp_segment_length < header_length_in_bytes_including_options)
					{
						drop!($packet, "TCP frame (segment) length is less than that indicated by its own header length, ie the TCP frame is cut short")
					}
					
					let options_length = header_length_in_bytes_including_options - size_of::<TcpFixedHeader>();
					
					(tcp_segment, tcp_segment_length, options_length)
				}
			}
		}
		
		macro_rules! finish_parsing_of_tcp_segment
		{
			($self: ident, $now: ident, $packet: ident, $minimum_tcp_maximum_segment_size_option: ident, $options_length: ident, $all_flags: ident, $source_internet_protocol_address: ident, $SEG: ident, $tcp_segment_length: ident) =>
			{
				{
					let options_data_pointer = $SEG.options_data_pointer();
					let tcp_options = parse_options!($packet, $minimum_tcp_maximum_segment_size_option, options_data_pointer, $options_length, $all_flags);
					ParsedTcpSegment::new($now, $packet, $self, $source_internet_protocol_address, $SEG, tcp_options, $options_length, $tcp_segment_length)
				}
			}
		}
		
		macro_rules! validate_connection_establishment_segment
		{
			($self: ident, $now: ident, $packet: ident, $minimum_tcp_maximum_segment_size_option: ident, $options_length: ident, $all_flags: ident, $source_internet_protocol_address: ident, $SEG: ident, $tcp_segment_length: ident) =>
			{
				{
					if $self.listening_server_port_combination_validity.port_combination_is_invalid($SEG.source_port_destination_port())
					{
						drop!($packet, "TCP connection establishment segment (Synchronize or Acknowledgment) is not from an acceptable combination of source (remote) port and destination (local) port")
					}
					
					finish_parsing_of_tcp_segment!($self, $now, $packet, $minimum_tcp_maximum_segment_size_option, $options_length, $all_flags, $source_internet_protocol_address, $SEG, $tcp_segment_length)
				}
			}
		}
		
		macro_rules! received_synchronize_when_state_is_listen_or_synchronize_received
		{
			($self: ident, $now: ident, $packet: ident, $minimum_tcp_maximum_segment_size_option: ident, $options_length: ident, $all_flags: ident, $source_internet_protocol_address: ident, $SEG: ident, $tcp_segment_length: ident, $explicit_congestion_notification_supported: expr) =>
			{
				{
					let mut parsed_tcp_segment = validate_connection_establishment_segment!($self, $now, $packet, $minimum_tcp_maximum_segment_size_option, $options_length, $all_flags, $source_internet_protocol_address, $SEG, $tcp_segment_length);
					parsed_tcp_segment.received_synchronize_when_state_is_listen_or_synchronize_received($explicit_congestion_notification_supported)
				}
			}
		}
		
		macro_rules! received_acknowledgment_when_state_is_listen_or_synchronize_received
		{
			($self: ident, $now: ident, $packet: ident, $minimum_tcp_maximum_segment_size_option: ident, $options_length: ident, $all_flags: ident, $source_internet_protocol_address: ident, $SEG: ident, $tcp_segment_length: ident, $push_flag_set: expr) =>
			{
				{
					if unlikely($self.transmission_control_blocks_at_maximum_capacity())
					{
						drop!($SEG, "TCP at maximum capacity")
					}
					
					let mut parsed_tcp_segment = validate_connection_establishment_segment!($self, $now, $packet, $minimum_tcp_maximum_segment_size_option, $options_length, $all_flags, $source_internet_protocol_address, $SEG, $tcp_segment_length);
					parsed_tcp_segment.received_acknowledgment_when_state_is_listen_or_synchronize_received($push_flag_set)
				}
			}
		}
		
		let (SEG, tcp_segment_length, options_length) = tcp_segment_of_valid_length!(packet, tcp_segment_offset);
		
		let all_flags = SEG.all_flags();
		
		if unlikely(all_flags.are_null())
		{
			drop!(packet, "TCP null scan")
		}
		
		if unlikely(SEG.are_reserved_bits_set_or_has_historic_nonce_sum_flag())
		{
			drop!(packet, "TCP reserved bits are set or has historic Nonce Sum (NS) flag")
		}
		
		if unlikely(all_flags.has_urgent_flag())
		{
			drop!(packet, "TCP URG flag is not supported")
		} else if cfg!(feature = "drop-urgent-pointer-field-non-zero")
		{
			if unlikely(SEG.urgent_pointer_if_URG_flag_set_is_not_zero())
			{
				drop!(packet, "TCP drop-urgent-pointer-field-non-zero")
			}
		}
		
		let source_internet_protocol_address = packet.source_internet_protocol_address();
		
		// TODO: this calculation copies bytes (from the reference to the InternetProtocolAddress) on the critical path if calculating the check sum in software.
		// This is only critical for IPv6.
		if unlikely(self.is_tcp_check_sum_invalid(SEG, layer_4_packet_size, source_internet_protocol_address))
		{
			drop!(packet, "TCP check sum is invalid")
		}
		
		let minimum_tcp_maximum_segment_size_option = TCBA::Address::MinimumTcpMaximumSegmentSizeOption;
		
		// TODO: this look up copies bytes (from the reference to the InternetProtocolAddress) on the critical path.
		// This is only critical for IPv6.
		match self.find_transmission_control_block_for_incoming_segment(source_internet_protocol_address, SEG)
		{
			// State is either Listen or SynchronizeReceived
			None => match all_flags
			{
				Flags::Synchronize => received_synchronize_when_state_is_listen_or_synchronize_received!(self, now, packet, minimum_tcp_maximum_segment_size_option, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length, false),
				
				Flags::SynchronizeExplicitCongestionEchoCongestionWindowReduced => received_synchronize_when_state_is_listen_or_synchronize_received!(self, now, packet, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length, true),
				
				// TODO: Add support for Explicit Congestion Notification, ECN.
				
				Flags::Acknowledgment => received_acknowledgment_when_state_is_listen_or_synchronize_received!(self, now, packet, minimum_tcp_maximum_segment_size_option, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length, false),
				
				Flags::AcknowledgmentPush => received_acknowledgment_when_state_is_listen_or_synchronize_received!(self, now, packet, minimum_tcp_maximum_segment_size_option, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length, true),
				
				// "A Finite State Machine Model of TCP Connections in the Transport Layer", J. Treurniet and J.H. Lefebvre, 2003 (http://cradpdf.drdc-rddc.gc.ca/PDFS/unc25/p520460.pdf) pages 5 & 6:-
				// State that whilst these states are techically valid, they are probably a scan.
				//
				// We VIOLATE RFC 973 here; to send a Reset is to either reveal to a potential attacker that we exist OR to inadvertently abort because of a spoofed packet an existing connection.
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
				// We VIOLATE RFC 973 here and do not send a 'Challenge ACK' under any circumstances: to do so would be to reveal that a syncookie we sent as an initial challenge is INVALID.
				Flags::Reset => drop!(packet, "TCP Reset segment when replying to a syncookie (ignored)"),
				
				_ => drop!(packet, "TCP segment contained a combination of flags invalid for replying to a syncookie"),
			}
			
			Some(transmission_control_block) =>
			{
				let mut parsed_tcp_segment = finish_parsing_of_tcp_segment!(self, now, packet, minimum_tcp_maximum_segment_size_option, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length);
				parsed_tcp_segment.process_tcp_segment_when_state_is_other_than_listen_or_synchronize_received(transmission_control_block.deref())
			}
		}
	}
	
	#[inline(always)]
	pub(crate) fn generate_initial_sequence_number(&self, remote_internet_protocol_address: TCBA::Address, remote_port_local_port: RemotePortLocalPort)
	{
		self.initial_sequence_number_generator.generate_initial_sequence_number(self.local_internet_protocol_address, remote_internet_protocol_address, remote_port_local_port)
	}
	
	#[inline(always)]
	fn is_tcp_check_sum_invalid(&self, SEG: &TcpSegment, layer_4_packet_size: usize, remote_internet_protocol_address: &TCBA::Address) -> bool
	{
		self.check_sum_layering.is_tcp_check_sum_invalid(SEG, layer_4_packet_size, remote_internet_protocol_address, &self.local_internet_protocol_address)
	}
	
	#[inline(always)]
	fn transmission_control_blocks_at_maximum_capacity(&self) -> bool
	{
		let transmission_control_blocks = self.transmission_control_blocks.borrow();
		transmission_control_blocks.len() == transmission_control_blocks.capacity()
	}
	
	#[inline(always)]
	pub(crate) fn new_transmission_control_block_for_incoming_segment(&self, transmission_control_block: TransmissionControlBlock<TCBA>)
	{
		let transmission_control_blocks = self.transmission_control_blocks.borrow_mut();
		let transmission_control_block = transmission_control_blocks.entry(transmission_control_block.key()).or_insert(transmission_control_block);
		let alarms = self.alarms();
		transmission_control_block.keep_alive_alarm.schedule(alarms, alarms.keep_alive_time);
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
	pub(crate) fn remove_transmission_control_block(&self, key: &TransmissionControlBlockKey<TCBA::Address>)
	{
		self.transmission_control_blocks.borrow_mut().remove(key);
	}
	
	#[inline(always)]
	pub(crate) fn alarms(&self) -> &Alarms<TCBA>
	{
		&self.alarms
	}
	
	#[inline(always)]
	pub(crate) fn validate_syncookie(&self, remote_internet_protocol_address: &TCBA::Address, SEG: &ParsedTcpSegment) -> Result<ParsedSynCookie, ()>
	{
		self.syn_cookie_protection.validate_syncookie_in_acknowledgment(&self.local_internet_protocol_address, remote_internet_protocol_address, SEG)
	}
	
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

impl<TCBA: TransmissionControlBlockAbstractions> Interface<TCBA>
{
	pub(crate) fn send_synchronize_acknowledgment(&self, now: MonotonicMillisecondTimestamp, packet: TCBA::Packet, remote_internet_protocol_address: &TCBA::Address, SEG: &ParsedTcpSegment, their_maximum_segment_size: Option<MaximumSegmentSizeOption>, their_window_scale: Option<WindowScaleOption>, their_selective_acknowledgment_permitted: bool, their_timestamp: Option<TimestampsOption>)
	{
		let mut our_tcp_segment = self.reuse_reversing_source_and_destination_addresses_for_tcp_segment(packet);
		
		let start_of_options_data_pointer = our_tcp_segment.options_data_pointer();
		
		let end_of_options_data_pointer =
			{
				let mut options_data_pointer = start_of_options_data_pointer;
				
				if likely(their_maximum_segment_size.is_some())
				{
					options_data_pointer = TcpSegment::write_maximum_segment_size_option(self.our_current_maximum_segment_size_without_fragmentation(remote_internet_protocol_address))
				}
				
				if likely(their_window_scale.is_some())
				{
					options_data_pointer = TcpSegment::write_window_scale_option(InitialWindowSize::Scale)
				}
				
				if likely(their_selective_acknowledgment_permitted)
				{
					options_data_pointer = TcpSegment::write_selective_acknowledgment_permitted_option(options_data_pointer);
				}
				
				if let Some(their_timestamp) = their_timestamp
				{
					options_data_pointer = TcpSegment::write_timestamps_option(options_data_pointer, Timestamping::initial_timestamps_option(their_timestamp.TSval))
				}
				
				options_data_pointer
			};
		
		let (padded_options_size, layer_4_packet_size) = TcpSegment::round_up_options_size_to_multiple_of_four_and_set_padding_to_zero(start_of_options_data_pointer, end_of_options_data_pointer, 0);
		
		// TODO: Send data on a SYNACK - call the event receiver, tell them the size of segment length we have - allow them to write some data to it.
		// TODO: Only for TCP Fast Open.
		let space_available_for_writing_payload = transmission_control_block.maximum_segment_size_to_send_to_remote - packet.internet_protocol_options_or_extension_headers_additional_overhead() - padded_options_size;
		
		{
			let syncookie = self.syn_cookie_protection.create_syn_cookie_for_synchronize_acnowledgment(now, &self.local_internet_protocol_address, remote_internet_protocol_address, SEG, their_maximum_segment_size, their_window_scale, their_selective_acknowledgment_permitted);
			
			our_tcp_segment.set_for_send(SEG.remote_port_local_port(), syncookie, SEG.SEQ + 1, padded_options_size, Flags::SynchronizeAcknowledgment, InitialWindowSize::Segment);
			
			self.check_sum_layering.calculate_in_software_and_set_if_required(&mut our_tcp_segment, layer_4_packet_size, &self.local_internet_protocol_address, transmission_control_block.remote_internet_protocol_address());
		}
		
		packet.set_layer_4_payload_length(layer_4_packet_size);
		
		// TODO: Send - and who frees the packet? What about re-transmission? Do we use DPDK's refcount in packets?
	}
	
	// TODO: Create SACKs.
	// See RFC 2018 but also has 1 errata https://www.rfc-editor.org/errata_search.php?rfc=2018
	pub(crate) fn send_acknowledgment(&self, packet: TCBA::Packet, transmission_control_block: &TransmissionControlBlock<TCBA>, flags: Flags, SEQ: WrappingSequenceNumber, ACK: WrappingSequenceNumber)
	{
		transmission_control_block.update_Last_ACK_sent(ACK);
		self.send_empty(packet, self.reuse_reversing_source_and_destination_addresses_for_tcp_segment(packet), transmission_control_block, flags, SEQ, ACK, None);
	}
	
	pub(crate) fn send_probe_without_packet_to_reuse(&self, transmission_control_block: &TransmissionControlBlock<TCBA>) -> Result<(), ()>
	{
		match self.create_for_tcp_segment(transmission_control_block.remote_internet_protocol_address())
		{
			Err(()) => Err(()),
			Ok((packet, our_tcp_segment)) =>
			{
				let SND = &transmission_control_block.SND;
				let RCV = &transmission_control_block.RCV;
				self.send_empty(packet, our_tcp_segment, transmission_control_block, Flags::PushAcknowledgment, SND.NXT - 1, RCV.NXT, None);
				Ok(())
			}
		}
	}
	
	/// RFC 5961: "If the RST bit is set and the sequence number does not exactly match the next expected sequence value, yet is within the current	receive window (RCV.NXT < SEG.SEQ < RCV.NXT+RCV.WND), TCP MUST send an acknowledgment (challenge ACK): <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>".
	pub(crate) fn send_challenge_acknowledgment(&self, packet: TCBA::Packet, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		let SND = &transmission_control_block.SND;
		let RCV = &transmission_control_block.RCV;
		self.send_empty(packet, self.reuse_reversing_source_and_destination_addresses_for_tcp_segment(packet), transmission_control_block, Flags::Acknowledgment, SND.NXT, RCV.NXT, None);
	}
	
	pub(crate) fn send_reset_without_packet_to_reuse(&self, transmission_control_block: &TransmissionControlBlock<TCBA>, SEQ: WrappingSequenceNumber) -> Result<(), ()>
	{
		match self.create_for_tcp_segment(transmission_control_block.remote_internet_protocol_address())
		{
			Err(()) => Err(()),
			Ok((packet, our_tcp_segment)) =>
			{
				self.send_reset_common(packet, our_tcp_segment, transmission_control_block, SEQ);
				Ok(())
			}
		}
	}
	
	pub(crate) fn send_reset(&self, packet: TCBA::Packet, transmission_control_block: &TransmissionControlBlock<TCBA>, SEQ: WrappingSequenceNumber)
	{
		self.send_reset_common(packet, self.reuse_reversing_source_and_destination_addresses_for_tcp_segment(packet), transmission_control_block, SEQ)
	}
	
	#[inline(always)]
	fn send_reset_common(&self, packet: TCBA::Packet, our_tcp_segment: &mut TcpSegment, transmission_control_block: &TransmissionControlBlock<TCBA>, SEQ: WrappingSequenceNumber)
	{
		debug_assert!(transmission_control_block.is_state_after_exchange_of_synchronized(), "We do not support sending Reset segments before the state has become Established");
		let RCV = &transmission_control_block.RCV;
		self.send_empty(packet, our_tcp_segment, transmission_control_block, Flags::Reset, SEQ, RCV.NXT, None)
	}
	
	#[inline(always)]
	fn send_empty(&self, packet: TCBA::Packet, our_tcp_segment: &mut TcpSegment, transmission_control_block: &TransmissionControlBlock<TCBA>, flags: Flags, SEQ: WrappingSequenceNumber, ACK: WrappingSequenceNumber, selective_acknowledgments: Option<SelectiveAcknowledgmentOption>)
	{
		let start_of_options_data_pointer = our_tcp_segment.options_data_pointer();
		
		let end_of_options_data_pointer =
		{
			let mut options_data_pointer = start_of_options_data_pointer;
			
			if likely(transmission_control_block.timestamps_are_required_in_all_segments_except_reset())
			{
				options_data_pointer = TcpSegment::write_timestamps_option(options_data_pointer, transmission_control_block.subsequent_timestamps_option())
			}
			
			if let Some(selective_acknowledgments_option) = selective_acknowledgments
			{
				options_data_pointer = TcpSegment::write_selective_acknowledgments_option(options_data_pointer, selective_acknowledgments_option)
			}
			
			options_data_pointer
		};
		
		let (padded_options_size, layer_4_packet_size) = TcpSegment::round_up_options_size_to_multiple_of_four_and_set_padding_to_zero(start_of_options_data_pointer, end_of_options_data_pointer, 0);
		
		// TODO: Combine multiple ACKs.
		// TODO: Send data on an ACK - call the event receiver, tell them the size of segment length we have - allow them to write some data to it.
		// TODO: Only for TCP Fast Open if this is the third part of a three-way handshake.
		let space_available_for_writing_payload = transmission_control_block.maximum_segment_size_to_send_to_remote - packet.internet_protocol_options_or_extension_headers_additional_overhead() - padded_options_size;
		
		{
			// TODO: Double mutable borrow (as RCV() borrow outside of this function).
			let RCV = &transmission_control_block.RCV;
			// RFC 7323, Section 2.3: "The window field (SEG.WND) of every outgoing segment, with the exception of <SYN> segments, MUST be right-shifted by Rcv.Wind.Shift bits:
			// SEG.WND = RCV.WND >> Rcv.Wind.Shift"
			let segment_window_size = RCV.WND >> RCV.Wind.Scale;
			
			our_tcp_segment.set_for_send(transmission_control_block.remote_port_local_port(), SEQ, ACK, padded_options_size, Flags::Acknowledgment, segment_window_size);
			
			self.check_sum_layering.calculate_in_software_and_set_if_required(&mut our_tcp_segment, layer_4_packet_size, &self.local_internet_protocol_address, transmission_control_block.remote_internet_protocol_address());
		}
		
		packet.set_layer_4_payload_length(layer_4_packet_size);
		
		// TODO: Add to a retransmission queue (if appropriate - not for challenge acks, keep alive probes, resets).
		
		// TODO: Send - and who frees the packet? What about re-transmission? Do we use DPDK's refcount in packets?
	}
	
	const TcpLayer4Protocol: u8 = 6;
	
	#[inline(always)]
	fn create_for_tcp_segment<'a>(&self, remote_internet_protocol_address: &TCBA::Address) -> Result<(TCBA::Packet, &'a mut TcpSegment), ()>
	{
		self.transmission_control_block_abstractions.create_packet(&self.local_internet_protocol_address, remote_internet_protocol_address, Self::TcpLayer4Protocol).map(|(packet, pointer_to_tcp_segment)| (packet, unsafe { &mut * (pointer_to_tcp_segment.as_ptr() as *mut TcpSegment) }))
	}
	
	#[inline(always)]
	fn reuse_reversing_source_and_destination_addresses_for_tcp_segment<'a>(&self, packet: TCBA::Packet) -> &'a mut TcpSegment
	{
		let pointer_to_tcp_segment = self.transmission_control_block_abstractions.reuse_packet_reversing_source_and_destination_addresses(Self::TcpLayer4Protocol, packet);
		
		unsafe { &mut * (pointer_to_tcp_segment.as_ptr() as *mut TcpSegment) }
	}
}
