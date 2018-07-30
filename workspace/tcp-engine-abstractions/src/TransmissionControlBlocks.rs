// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Logic relating to management of Transmission Control Blocks (TCBs).
#[derive(Debug)]
pub struct TransmissionControlBlocks<TCBA: TransmissionControlBlockAbstractions, TCB: CreateTransmissionControlBlock<TCBA::Address> + ConnectionIdentification<TCBA::Address> + RecentConnectionDataProvider<TCBA::Address>>
{
	transmission_control_blocks: UnsafeCell<BoundedHashMap<TransmissionControlBlockKey<TCBA::Address>, TCB>>,
	transmission_control_blocks_send_buffers: Rc<MagicRingBuffersArena>,
	source_port_chooser: SourcePortChooser<TCBA::Address>,
	recent_connections_congestion_data: RecentConnectionDataCache<TCBA::Address>,
	initial_sequence_number_generator: InitialSequenceNumberGenerator,
}

impl<TCBA: TransmissionControlBlockAbstractions, TCB: CreateTransmissionControlBlock<TCBA::Address> + ConnectionIdentification<TCBA::Address> + RecentConnectionDataProvider<TCBA::Address>> TransmissionControlBlocks<TCBA, TCB>
{
	/// Creates a new instance.
	#[inline(always)]
	pub fn new(transmission_control_blocks_map_capacity: usize, maximum_recent_connections_capacity: usize) -> Self
	{
		const SendBufferSize: usize = 256 * 1024;
		
		Self
		{
			transmission_control_blocks: UnsafeCell::new(BoundedHashMap::new(transmission_control_blocks_map_capacity)),
			transmission_control_blocks_send_buffers: MagicRingBuffersArena::new(transmission_control_blocks_map_capacity, SendBufferSize).expect("Could not allocate memory for send buffers"),
			source_port_chooser: SourcePortChooser::new(maximum_recent_connections_capacity),
			recent_connections_congestion_data: RecentConnectionDataCache::new(maximum_recent_connections_capacity, SourcePortChooser::<TCBA::Address>::OutboundConnectionExpiryPeriodIsRfc793DoubleMaximumSegmentLifetime),
			initial_sequence_number_generator: InitialSequenceNumberGenerator::default(),
		}
	}
	
	/// Find a transmission control block (TCB) for an incoming segment.
	#[inline(always)]
	pub fn find_transmission_control_block_for_incoming_segment(&self, remote_internet_protocol_address: &TCBA::Address, SEG: &TcpSegment) -> Option<&mut TCB>
	{
		let key = TransmissionControlBlockKey::from_incoming_segment(remote_internet_protocol_address, SEG);
		self.transmission_control_blocks_mutable_reference().get_mut(&key)
	}
	
	/// Are we at maximum capacity?
	#[inline(always)]
	pub fn at_maximum_capacity(&self) -> bool
	{
		self.transmission_control_blocks_reference().is_full()
	}
	
	/// Create a new transmission control block for an outgoing (client) connection.
	#[inline(always)]
	pub fn new_transmission_control_block_for_outgoing_client_connection(&self, remote_internet_protocol_address: TCBA::Address, remote_port: NetworkEndianU16, now: MonotonicMillisecondTimestamp, explicit_congestion_notification_supported: bool, connection_time_out: MillisecondDuration, listening_server_port_combination_validity: &PortCombinationValidity, authentication_pre_shared_secret_keys: &AuthenticationPreSharedSecretKeys<TCBA::Address>, maximum_segment_size_table: &MaximumSegmentSizeTable<TCBA::Address, TCBA::PMTUTable>, local_internet_protocol_address: &TCBA::Address) -> Result<(), ()>
	{
		self.debug_assert_not_at_maximum_capacity();
		
		let transmission_control_block = self.add
		({
			let remote_port_local_port =
			{
				let local_port = self.source_port_chooser.pick_a_source_port_for_a_new_outgoing_connection(now, &remote_internet_protocol_address, remote_port, listening_server_port_combination_validity)?;
				RemotePortLocalPort::from_remote_port_local_port(remote_port, local_port)
			};
			
			let key = TransmissionControlBlockKey::for_client(remote_internet_protocol_address, remote_port_local_port);
			
			let maximum_segment_size_to_send_to_remote = maximum_segment_size_table.maximum_segment_size_without_fragmentation(&remote_internet_protocol_address);
			let recent_connection_data = self.recent_connection_data(now, &remote_internet_protocol_address);
			let md5_authentication_key = authentication_pre_shared_secret_keys.find_md5_authentication_key(&remote_internet_protocol_address, remote_port_local_port.remote_port()).map(|key_reference| key_reference.clone());
			let magic_ring_buffer = self.allocate_a_send_buffer();
			let congestion_control = Self::congestion_control(explicit_congestion_notification_supported, now, maximum_segment_size_to_send_to_remote, recent_connection_data);
			
			let ISS = self.generate_initial_sequence_number(local_internet_protocol_address, &remote_internet_protocol_address, remote_port_local_port);
			
			TCB::new_for_closed_to_synchronize_sent(key, now, maximum_segment_size_to_send_to_remote, recent_connection_data, md5_authentication_key, magic_ring_buffer, congestion_control, ISS)
		});
		
		// TODO: Schedule alarms (use connection_time_out).
		
		Ok(())
	}
	
	/// Create a new transmission control block for an incoming (server) connection.
	#[inline(always)]
	pub fn new_transmission_control_block_for_incoming_segment(&self, source_internet_protocol_address: &TCBA::Address, SEG: &TcpSegment, SEG_WND: SegmentWindowSize, tcp_options: &TcpOptions, parsed_syncookie: ParsedSynCookie, now: MonotonicMillisecondTimestamp, md5_authentication_key: Option<Rc<Md5PreSharedSecretKey>>, maximum_segment_size_table: &MaximumSegmentSizeTable<TCBA::Address, TCBA::PMTUTable>) -> &mut TCB
	{
		self.debug_assert_not_at_maximum_capacity();
		
		let transmission_control_block = self.add
		({
			let remote_internet_protocol_address = source_internet_protocol_address;
			
			let key = TransmissionControlBlockKey::from_incoming_segment(remote_internet_protocol_address, SEG);
			
			let maximum_segment_size_to_send_to_remote = maximum_segment_size_table.maximum_segment_size_to_send_to_remote_u16(parsed_syncookie.their_maximum_segment_size, remote_internet_protocol_address);
			let recent_connection_data = self.recent_connection_data(now, remote_internet_protocol_address);
			let md5_authentication_key = md5_authentication_key.map(|rc| rc.clone());
			let magic_ring_buffer = self.allocate_a_send_buffer();
			let congestion_control = Self::congestion_control(parsed_syncookie.explicit_congestion_notification_supported, now, maximum_segment_size_to_send_to_remote, recent_connection_data);
			
			TCB::new_for_sychronize_received_to_established(key, now, maximum_segment_size_to_send_to_remote, recent_connection_data, md5_authentication_key, magic_ring_buffer, congestion_control, SEG_WND, tcp_options, parsed_syncookie)
		});
		
		// TODO: Schedule alarms.
		
		transmission_control_block
	}
	
	/// Removes a transmission control block from the managed index.
	///
	/// A caller is responsible for freeing the data within the transmission control block (typicaly this involves freeing alarms).
	#[inline(always)]
	pub fn remove_transmission_control_block(&self, key: &TransmissionControlBlockKey<TCBA::Address>, now: MonotonicMillisecondTimestamp) -> TCB
	{
		let transmission_control_block = self.transmission_control_blocks_mutable_reference().remove(key).unwrap();
		
		self.update_recent_connection_data(&transmission_control_block, now);
		self.source_port_chooser.update(&transmission_control_block, now);
		transmission_control_block
	}
	
	#[inline(always)]
	fn debug_assert_not_at_maximum_capacity(&self)
	{
		debug_assert!(!self.at_maximum_capacity(), "at_maximum_capacity() should have already been checked");
	}
	
	#[inline(always)]
	fn add(&self, transmission_control_block: TCB) -> &mut TCB
	{
		self.transmission_control_blocks_mutable_reference().insert_uniquely_and_return_mutable_reference(transmission_control_block.key().clone(), transmission_control_block)
	}
	
	#[inline(always)]
	fn generate_initial_sequence_number(&self, local_internet_protocol_address: &TCBA::Address, remote_internet_protocol_address: &TCBA::Address, remote_port_local_port: RemotePortLocalPort) -> WrappingSequenceNumber
	{
		self.initial_sequence_number_generator.generate_initial_sequence_number(local_internet_protocol_address, remote_internet_protocol_address, remote_port_local_port)
	}
	
	#[inline(always)]
	fn recent_connection_data(&self, now: MonotonicMillisecondTimestamp, remote_internet_protocol_address: &TCBA::Address) -> &RecentConnectionData
	{
		self.recent_connections_congestion_data.get(now, remote_internet_protocol_address)
	}
	
	#[inline(always)]
	fn update_recent_connection_data(&self, transmission_control_block: &TCB, now: MonotonicMillisecondTimestamp)
	{
		self.recent_connections_congestion_data.update(transmission_control_block, now)
	}
	
	#[inline(always)]
	fn allocate_a_send_buffer(&self) -> MagicRingBuffer
	{
		MagicRingBuffersArena::allocate(&self.transmission_control_blocks_send_buffers)
	}
	
	#[inline(always)]
	fn congestion_control(explicit_congestion_notification_supported: bool, now: MonotonicMillisecondTimestamp, maximum_segment_size_to_send_to_remote: u16, recent_connection_data: &RecentConnectionData) -> CongestionControl
	{
		const InitialCongestionWindowAlgorithm: InitialCongestionWindowAlgorithm = InitialCongestionWindowAlgorithm::RFC_6928;
		
		CongestionControl::new(explicit_congestion_notification_supported, InitialCongestionWindowAlgorithm, now, maximum_segment_size_to_send_to_remote, recent_connection_data)
	}
	
	#[inline(always)]
	fn transmission_control_blocks_reference(&self) -> &BoundedHashMap<TransmissionControlBlockKey<TCBA::Address>, TCB>
	{
		unsafe { & * self.transmission_control_blocks.get() }
	}
	
	#[inline(always)]
	fn transmission_control_blocks_mutable_reference(&self) -> &mut BoundedHashMap<TransmissionControlBlockKey<TCBA::Address>, TCB>
	{
		unsafe { &mut * self.transmission_control_blocks.get() }
	}
}
