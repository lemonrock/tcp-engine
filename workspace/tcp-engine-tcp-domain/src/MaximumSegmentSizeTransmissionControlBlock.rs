// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Maximum Segment Size (MSS).
pub trait MaximumSegmentSizeTransmissionControlBlock<Address: InternetProtocolAddress>: StateTransmissionControlBlock + ConnectionIdentification<Address>
{
	/// Only valid to use when connecting as a client.
	#[inline(always)]
	fn our_offered_maximum_segment_size_when_initiating_connections(&self) -> MaximumSegmentSizeOption
	{
		self.debug_assert_action_is_only_valid_in_sychronize_sent_state();
		self.debug_assert_we_are_the_client();
		
		MaximumSegmentSizeOption::from(self.get_field_maximum_segment_size_to_send_to_remote())
	}
	
	/// Only valid to use when connecting as a client.
	#[inline(always)]
	fn set_maximum_segment_size_to_send_to_remote(&mut self, maximum_segment_size_to_send_to_remote: u16)
	{
		self.debug_assert_action_is_only_valid_in_sychronize_sent_state();
		self.debug_assert_we_are_the_client();
		
		self.set_field_maximum_segment_size_to_send_to_remote(maximum_segment_size_to_send_to_remote)
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn get_field_maximum_segment_size_to_send_to_remote(&self) -> u16;
	
	#[doc(hidden)]
	#[inline(always)]
	fn set_field_maximum_segment_size_to_send_to_remote(&mut self, value: u16);
}
