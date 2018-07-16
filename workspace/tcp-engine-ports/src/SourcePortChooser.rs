// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Chooses sources ports for new outgoing connections securely and randomly in accordance with RFC 6056.
#[derive(Debug)]
pub struct SourcePortChooser<Address: InternetProtocolAddress>
{
	cache: UnsafeCell<LeastRecentlyUsedCacheWithExpiry<(Address, NetworkEndianU16), PortBitSet>>,
}

impl<Address: InternetProtocolAddress> SourcePortChooser<Address>
{
	/// A four-minute value.
	pub const OutboundConnectionExpiryPeriodIsRfc793DoubleMaximumSegmentLifetime: MillisecondDuration = MillisecondDuration::FourMinutes;
	
	/// Create a new instance.
	#[inline(always)]
	pub fn new(maximum_capacity: usize) -> Self
	{
		Self
		{
			cache: UnsafeCell::new(LeastRecentlyUsedCacheWithExpiry::new(maximum_capacity, Self::OutboundConnectionExpiryPeriodIsRfc793DoubleMaximumSegmentLifetime)),
		}
	}
	
	/// RFC 6056: Section 3.2: "... ephemeral port selection algorithms should use the whole range 1024-65535.
	/// ...
	/// port numbers that may be needed for providing a particular service at the local host SHOULD NOT be included in the pool of port numbers available for ephemeral port randomization".
	///
	/// `listening_server_port_combination_validity.valid_local_ports` represents this requirement.
	#[inline(always)]
	pub fn pick_a_source_port_for_a_new_outgoing_connection(&self, now: MonotonicMillisecondTimestamp, remote_internet_protocol_address: &Address, remote_port: NetworkEndianU16, listening_server_port_combination_validity: &PortCombinationValidity) -> Result<NetworkEndianU16, ()>
	{
		let key = (*remote_internet_protocol_address, remote_port);
		let valid_local_ports = &listening_server_port_combination_validity.valid_local_ports;
	
		let source_port = if let Some(source_ports_port_bit_set) = self.cache().get_mut(now, &key)
		{
			let source_port = match source_ports_port_bit_set.union(valid_local_ports).find_unused_securely_randomly(1024)
			{
				None => return Err(()),
				Some(source_port) => source_port,
			};
			
			source_ports_port_bit_set.insert(source_port);
			
			source_port
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
			
			self.cache().insert(now, key, source_ports_port_bit_set);
			
			source_port
		};
		
		Ok(NetworkEndianU16::from_native_endian(source_port))
	}
	
	/// Update recent outgoing connection source port information.
	#[inline(always)]
	pub fn update(&self, transmission_control_block: &impl ConnectionIdentification<Address>, now: MonotonicMillisecondTimestamp)
	{
		if transmission_control_block.we_are_the_listener()
		{
			return
		}
		
		let remote_internet_protocol_address = transmission_control_block.remote_internet_protocol_address();
		let remote_port_local_port = transmission_control_block.remote_port_local_port();
		
		let source_port = remote_port_local_port.local_port().to_native_endian();
		
		let key = (*remote_internet_protocol_address, remote_port_local_port.remote_port());
		
		if let Some(source_ports_port_bit_set) = self.cache().get_mut(now, &key)
		{
			source_ports_port_bit_set.insert(source_port)
		}
		else
		{
			let mut source_ports_port_bit_set = PortBitSet::new_with_rfc_6056_ephemeral_ports_available();
			
			source_ports_port_bit_set.insert(source_port);
			
			self.cache().insert(now, key, source_ports_port_bit_set);
		}
	}
	
	#[inline(always)]
	fn cache(&self) -> &mut LeastRecentlyUsedCacheWithExpiry<(Address, NetworkEndianU16), PortBitSet>
	{
		unsafe { &mut * self.cache.get() }
	}
}
