// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Where is check sum validation and calculation performed?
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum CheckSumLayering
{
	/// Is this check sum validated by the underlying ethernet device (eg by a TCP Offload Engine)?
	ByEthernetDevice,
	
	/// Is this check sum validated by the software interface?
	BySoftwareInterface,
}

impl CheckSumLayering
{
	/// `source_internet_protocol_address` and `destination_internet_protocol_address` are from the point of view of the fields in the Internet Protocol version 4 header or the Internet Protocol version 6 header.
	#[inline(always)]
	pub fn is_tcp_check_sum_invalid<Address: InternetProtocolAddress>(self, SEG: &TcpSegment, layer_4_packet_size: usize, source_internet_protocol_address: &Address, destination_internet_protocol_address: &Address) -> bool
	{
		use self::CheckSumLayering::*;
		
		match self
		{
			ByEthernetDevice => false,
			
			BySoftwareInterface =>
			{
				let internet_packet_payload_pointer = unsafe { NonNull::new_unchecked(SEG as *const TcpSegment as *const u8 as *mut u8) };
				
				let check_sum = Address::calculate_internet_protocol_tcp_check_sum(source_internet_protocol_address, destination_internet_protocol_address, internet_packet_payload_pointer, layer_4_packet_size);
				
				check_sum.validates()
			}
		}
	}
	
	/// Calculate check sum in software and set it on the TcpSegment.
	///
	/// Assumes TcpSegment check sum is zero.
	#[inline(always)]
	pub fn calculate_in_software_and_set_if_required<Address: InternetProtocolAddress>(self, outgoing_tcp_segment: &mut TcpSegment, layer_4_packet_size: usize, source_internet_protocol_address: &Address, destination_internet_protocol_address: &Address)
	{
		use self::CheckSumLayering::*;
		
		match self
		{
			ByEthernetDevice => (),
			
			BySoftwareInterface =>
			{
				let internet_packet_payload_pointer = unsafe { NonNull::new_unchecked(outgoing_tcp_segment as *const TcpSegment as *const u8 as *mut u8) };
				
				let check_sum = Address::calculate_internet_protocol_tcp_check_sum(source_internet_protocol_address, destination_internet_protocol_address, internet_packet_payload_pointer, layer_4_packet_size);
				
				outgoing_tcp_segment.set_check_sum(check_sum)
			}
		}
	}
}
