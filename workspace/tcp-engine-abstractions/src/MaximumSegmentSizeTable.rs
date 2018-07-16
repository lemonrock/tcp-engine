// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A maximum segment size table.
#[derive(Debug)]
pub struct MaximumSegmentSizeTable<Address: InternetProtocolAddress, PMTUTable: PathMaximumTransmissionUnitTable<Address>>
{
	path_maximum_transmission_unit_table: PMTUTable,
	phantom_data: PhantomData<Address>,
}

impl<Address: InternetProtocolAddress, PMTUTable: PathMaximumTransmissionUnitTable<Address>> MaximumSegmentSizeTable<Address, PMTUTable>
{
	/// Constructs a new instance.
	#[inline(always)]
	pub const fn new(path_maximum_transmission_unit_table: PMTUTable) -> Self
	{
		Self
		{
			path_maximum_transmission_unit_table,
			phantom_data: PhantomData,
		}
	}
	
	/// Maximum segment size to send to remote.
	#[inline(always)]
	pub fn maximum_segment_size_to_send_to_remote(&self, their_maximum_segment_size_options: Option<MaximumSegmentSizeOption>, remote_internet_protocol_address: &Address) -> u16
	{
		let their_maximum_segment_size = match their_maximum_segment_size_options
		{
			None => Address::DefaultMaximumSegmentSizeIfNoneSpecified.to_native_endian(),
			
			Some(their_maximum_segment_size_option) => their_maximum_segment_size_option.to_native_endian(),
		};
		
		self.maximum_segment_size_to_send_to_remote_u16(their_maximum_segment_size, remote_internet_protocol_address)
	}
	
	/// Maximum segment size to send to remote (as u16).
	#[inline(always)]
	pub fn maximum_segment_size_to_send_to_remote_u16(&self, their_maximum_segment_size: u16, remote_internet_protocol_address: &Address) -> u16
	{
		min(their_maximum_segment_size, self.maximum_segment_size_without_fragmentation(remote_internet_protocol_address))
	}
	
	/// RFC 6691, Section 2: "When calculating the value to put in the TCP MSS option, the MTU value SHOULD be decreased by only the size of the fixed IP and TCP headers and SHOULD NOT be decreased to account for any possible IP or TCP options; conversely, the sender MUST reduce the TCP data length to account for any IP or TCP options that it is including in the packets that it sends.
	/// ... the goal is to avoid IP-level fragmentation of TCP packets".
	#[inline(always)]
	pub fn maximum_segment_size_without_fragmentation(&self, remote_internet_protocol_address: &Address) -> u16
	{
		let path_maximum_transmission_unit = self.path_maximum_transmission_unit_table.current_path_maximum_transmission_unit(remote_internet_protocol_address);
		
		debug_assert!(path_maximum_transmission_unit >= Address::MinimumPathMaximumTransmissionUnitSize, "path_maximum_transmission_unit '{}' is less than MinimumPathMaximumTransmissionUnitSize '{}'", path_maximum_transmission_unit, Address::MinimumPathMaximumTransmissionUnitSize);
		
		let minimum_overhead_excluding_ip_options_ip_headers_and_tcp_options = Address::SmallestLayer3HeaderSize + (size_of::<TcpFixedHeader>() as u16);
		
		debug_assert!(path_maximum_transmission_unit > minimum_overhead_excluding_ip_options_ip_headers_and_tcp_options, "path_maximum_transmission_unit '{}' is equal to or less than packet_headers_length_excluding_tcp_options '{}'", path_maximum_transmission_unit, minimum_overhead_excluding_ip_options_ip_headers_and_tcp_options);
		path_maximum_transmission_unit - minimum_overhead_excluding_ip_options_ip_headers_and_tcp_options
	}
}
