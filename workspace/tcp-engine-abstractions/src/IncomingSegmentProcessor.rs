// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Processes incoming segments.
#[derive(Debug)]
pub struct IncomingSegmentProcessor
{
	// TODO: Not a device-level property but a property of the packet; some packets will not have a checksum for various reasons, eg LRO.
	check_sum_layering: CheckSumLayering,
}

impl IncomingSegmentProcessor
{
	/// NOTE: RFC 2675 IPv6 jumbograms are not supported.
	///
	/// This logic DOES NOT validate:-
	///
	/// * that source and destination addreses are permitted, eg are not multicast (this is the responsibility of lower layers);
	/// * that the source and destination addresses (and ports) are not the same.
	///
	/// `layer_4_packet_size` is NOT the same as the IPv6 payload size; in this case, it is the IPv6 payload size LESS the extensions headers size.
	#[inline(always)]
	pub fn process_incoming_segment<ISA: IncomingSegmentAction<TCBA, I>, I: NetworkDeviceInterface<TCBA>, TCBA: TransmissionControlBlockAbstractions>(&self, now: MonotonicMillisecondTimestamp, packet: TCBA::Packet, layer_4_packet_size: usize, interface: &I)
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
					
					if unlikely!($tcp_segment_length < size_of::<TcpFixedHeader>())
					{
						drop!($self, $packet, "TCP frame (segment) is shorted than minimum size of TCP fixed header (excluding options)")
					}
					
					let tcp_segment = $packet.offset_into_packet_headers_reference::<TcpSegment>(tcp_segment_offset);
					
					let raw_data_length_bytes = tcp_segment.raw_data_length_bytes();
					
					if unlikely!(raw_data_length_bytes < (5 << 4))
					{
						drop!($self, $packet, "TCP header length 32-bit words was too small (less than 5)")
					}
					
					let header_length_in_bytes_including_options = raw_data_length_bytes as usize;
					
					if unlikely!($tcp_segment_length < header_length_in_bytes_including_options)
					{
						drop!($self, $packet, "TCP frame (segment) length is less than that indicated by its own header length, ie the TCP frame is cut short")
					}
					
					let options_length = header_length_in_bytes_including_options - size_of::<TcpFixedHeader>();
					
					(tcp_segment, $tcp_segment_length, options_length)
				}
			}
		}
		
		macro_rules! finish_parsing_of_tcp_segment
		{
			($self: ident, $interface: ident, $now: ident, $packet: ident, $smallest_acceptable_tcp_maximum_segment_size_option: ident, $options_length: ident, $all_flags: ident, $source_internet_protocol_address: ident, $SEG: ident, $tcp_segment_length: ident) =>
			{
				{
					let options_data_pointer = $SEG.options_data_pointer();
					let tcp_options = parse_options!($self, $packet, $smallest_acceptable_tcp_maximum_segment_size_option, options_data_pointer, $options_length, $all_flags);
					ISA::new($now, $packet, $interface, $source_internet_protocol_address, $SEG, tcp_options, $options_length, $tcp_segment_length)
				}
			}
		}
		
		macro_rules! validate_connection_establishment_segment
		{
			($self: ident, $interface: ident, $listening_server_port_combination_validity: ident, $now: ident, $packet: ident, $smallest_acceptable_tcp_maximum_segment_size_option: ident, $options_length: ident, $all_flags: ident, $source_internet_protocol_address: ident, $SEG: ident, $tcp_segment_length: ident) =>
			{
				{
					if $listening_server_port_combination_validity.port_combination_is_invalid($SEG.source_port_destination_port())
					{
						drop!($self, $packet, "TCP connection establishment segment (Synchronize or Acknowledgment) is not from an acceptable combination of source (remote) port and destination (local) port")
					}
					
					finish_parsing_of_tcp_segment!($self, $interface, $now, $packet, $smallest_acceptable_tcp_maximum_segment_size_option, $options_length, $all_flags, $source_internet_protocol_address, $SEG, $tcp_segment_length)
				}
			}
		}
		
		macro_rules! received_synchronize_when_state_is_listen_or_synchronize_received
		{
			($self: ident, $interface: ident, $listening_server_port_combination_validity: ident, $now: ident, $packet: ident, $smallest_acceptable_tcp_maximum_segment_size_option: ident, $options_length: ident, $all_flags: ident, $source_internet_protocol_address: ident, $SEG: ident, $tcp_segment_length: ident, $explicit_congestion_notification_supported: expr) =>
			{
				{
					// Implied from RFC 793 Section 3.7 Open Call CLOSED State page 54: "A SYN segment of the form <SEQ=ISS><CTL=SYN> is sent".
					if unlikely!($SEG.ACK().is_not_zero())
					{
						drop!($self, $packet, "TCP Synchronize segment has a non-zero initial ACK field")
					}
					
					if cfg!(not(feature = "rfc-8311-permit-explicit-congestion-markers-on-all-packets"))
					{
						// RFC 3168 Section 6.1.1: "A host MUST NOT set ECT on SYN or SYN-ACK packets".
						if unlikely!($packet.explicit_congestion_notification::<TCBA::Address>().is_ect_or_congestion_experienced_set())
						{
							drop!($self, $packet, "TCP packet has an Internet Protocol Explicit Congestion Notification (ECN) set for a Synchronize segment in violation of RFC 3168")
						}
					}
					
					let mut incoming_segment_action = validate_connection_establishment_segment!($self, $interface, $listening_server_port_combination_validity, $now, $packet, $smallest_acceptable_tcp_maximum_segment_size_option, $options_length, $all_flags, $source_internet_protocol_address, $SEG, $tcp_segment_length);
					let md5_authentication_key = $interface.find_md5_authentication_key($source_internet_protocol_address, $SEG.source_port_destination_port().destination_port());
					incoming_segment_action.received_synchronize_when_state_is_listen_or_synchronize_received(md5_authentication_key, $explicit_congestion_notification_supported)
				}
			}
		}
		
		macro_rules! received_acknowledgment_when_state_is_listen_or_synchronize_received
		{
			($self: ident, $interface: ident, $listening_server_port_combination_validity: ident, $now: ident, $packet: ident, $smallest_acceptable_tcp_maximum_segment_size_option: ident, $options_length: ident, $all_flags: ident, $source_internet_protocol_address: ident, $SEG: ident, $tcp_segment_length: ident) =>
			{
				{
					let mut incoming_segment_action = validate_connection_establishment_segment!($self, $interface, $listening_server_port_combination_validity, $now, $packet, $smallest_acceptable_tcp_maximum_segment_size_option, $options_length, $all_flags, $source_internet_protocol_address, $SEG, $tcp_segment_length);
					let md5_authentication_key = $interface.find_md5_authentication_key($source_internet_protocol_address, $SEG.source_port_destination_port().destination_port());
					incoming_segment_action.received_acknowledgment_when_state_is_listen_or_synchronize_received(md5_authentication_key)
				}
			}
		}
		
		let (SEG, tcp_segment_length, options_length) = tcp_segment_of_valid_length!(self, packet, layer_4_packet_size);
		
		let all_flags = SEG.all_flags();
		
		if unlikely!(all_flags.are_null())
		{
			drop!(self, packet, "TCP null scan")
		}
		
		// RFC 3360 Section 2.1: "... the Reserved field should be zero when sent and ignored when received, unless specified otherwise by future standards actions".
		//
		// We VIOLATE the RFC here.
		if unlikely!(SEG.are_reserved_bits_set_or_has_historic_nonce_sum_flag())
		{
			// RFC 3360 Section 2.1: "... the phrasing in RFC 793 does not permit sending resets in response to TCP	packets with a non-zero Reserved field, as is explained in the section above".
			drop!(self, packet, "TCP reserved bits are set or have historic Nonce Sum (NS) flag set")
		}
		
		if unlikely!(all_flags.has_urgent_flag())
		{
			drop!(self, packet, "TCP URG flag is not supported")
		}
		else if cfg!(feature = "drop-urgent-pointer-field-non-zero")
		{
			if unlikely!(SEG.urgent_pointer_if_URG_flag_set_is_not_zero())
			{
				drop!(self, packet, "TCP drop-urgent-pointer-field-non-zero")
			}
		}
		
		let source_internet_protocol_address = packet.source_internet_protocol_address();
		
		if unlikely!(self.check_sum_layering.is_tcp_check_sum_invalid(SEG, layer_4_packet_size, source_internet_protocol_address, interface.local_internet_protocol_address()))
		{
			drop!(self, packet, "TCP check sum is invalid")
		}
		
		let smallest_acceptable_tcp_maximum_segment_size_option = MaximumSegmentSizeOption::from(TCBA::Address::SmallestAcceptableMaximumSegmentSize);
		
		let listening_server_port_combination_validity = interface.listening_server_port_combination_validity();
		
		match interface.find_transmission_control_block_for_incoming_segment(source_internet_protocol_address, SEG)
		{
			// State is either Listen or SynchronizeReceived.
			None => match all_flags
			{
				Flags::Synchronize =>
				received_synchronize_when_state_is_listen_or_synchronize_received!(self, interface, listening_server_port_combination_validity, now, packet, smallest_acceptable_tcp_maximum_segment_size_option, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length, false),
				
				Flags::SynchronizeExplicitCongestionEchoCongestionWindowReduced =>
				received_synchronize_when_state_is_listen_or_synchronize_received!(self, interface, listening_server_port_combination_validity, now, packet, smallest_acceptable_tcp_maximum_segment_size_option, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length, true),
				
				Flags::Acknowledgment | Flags::AcknowledgmentPush =>
				{
					if unlikely!(interface.transmission_control_blocks_at_maximum_capacity())
					{
						drop!(self, SEG, "TCP at maximum capacity")
					}
					
					received_acknowledgment_when_state_is_listen_or_synchronize_received!(self, interface, listening_server_port_combination_validity, now, packet, smallest_acceptable_tcp_maximum_segment_size_option, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length)
				}
				
				// "A Finite State Machine Model of TCP Connections in the Transport Layer", J. Treurniet and J. H. Lefebvre, 2003 (http://cradpdf.drdc-rddc.gc.ca/PDFS/unc25/p520460.pdf) pages 5 & 6:-
				// State that whilst these states are techically valid, they are probably a scan.
				//
				// We VIOLATE RFC 793 here; to send a Reset is to either reveal to a potential attacker that we exist OR to inadvertently abort because of a spoofed packet an existing connection.
				//
				// As such, rather than sending a Reset (which is technically the correct thing to do), we just drop the packet.
				Flags::FinishAcknowledgment | Flags::FinishAcknowledgmentPush | Flags::ResetAcknowledgment => drop!(self, packet, "TCP FinishAcknowledgment, FinishAcknowledgmentPush or ResetAcknowledgment segment when replying to a syncookie (ignored)"),
				
				// RFC 5961 Section 3.2 Page 8:-
				// "In all states except SYN-SENT, all reset (RST) packets are validated by checking their SEQ-fields [sequence numbers].
				// A reset is valid if its sequence number exactly matches the next expected sequence number.
				// If the RST arrives and its sequence number field does NOT match the next expected sequence number but is within the window, then the receiver should generate an ACK \*.
				// In all other cases, where the SEQ-field does not match and is outside the window, the receiver MUST silently discard the segment."
				//
				// \* This is known as a 'Challenge ACK'.
				//
				// We VIOLATE RFC 5961 here and do not send a 'Challenge ACK' under any circumstances: to do so would be to reveal that a syncookie we sent as an initial challenge is INVALID.
				Flags::Reset => drop!(self, packet, "TCP Reset segment when replying to a syncookie (ignored)"),
				
				_ => drop!(self, packet, "TCP segment contained a combination of flags invalid for replying to a syncookie"),
			}
			
			Some(transmission_control_block) =>
			{
				let mut incoming_segment_action = finish_parsing_of_tcp_segment!(self, interface, now, packet, smallest_acceptable_tcp_maximum_segment_size_option, options_length, all_flags, source_internet_protocol_address, SEG, tcp_segment_length);
				
				incoming_segment_action.process_tcp_segment_when_state_is_other_than_listen_or_synchronize_received(transmission_control_block)
			}
		}
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


