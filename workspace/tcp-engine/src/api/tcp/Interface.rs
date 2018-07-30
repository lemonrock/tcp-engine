// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
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
























