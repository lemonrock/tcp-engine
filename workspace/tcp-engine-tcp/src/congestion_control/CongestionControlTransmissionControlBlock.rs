// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Congestion Control.
pub trait CongestionControlTransmissionControlBlock
{
	#[allow(non_snake_case)]
	#[doc(hidden)]
	#[inline(always)]
	fn increment_duplicate_acknowledgments_received_without_any_intervening_acknwoledgments_which_moved_SND_UNA(&mut self)
	{
		self.congestion_control_mutable_reference().increment_duplicate_acknowledgments_received_without_any_intervening_acknwoledgments_which_moved_SND_UNA()
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn reset_congestion_window_to_loss_window_because_retransmission_timed_out(&mut self)
	{
		self.congestion_control_mutable_reference().reset_congestion_window_to_loss_window_because_retransmission_timed_out()
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn bytes_sent_in_payload_in_a_segment_which_is_not_a_zero_window_probe_or_retransmission(&mut self, increase_flight_size_by_amount_of_bytes: u32)
	{
		self.congestion_control_mutable_reference().bytes_sent_in_payload_in_a_segment_which_is_not_a_zero_window_probe_or_retransmission(increase_flight_size_by_amount_of_bytes)
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn rfc_5681_section_7_paragaph_6_set_ssthresh_to_half_of_flight_size_on_first_retransmission(&mut self)
	{
		self.congestion_control_mutable_reference().rfc_5681_section_7_paragaph_6_set_ssthresh_to_half_of_flight_size_on_first_retransmission();
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn congestion_control_reference(&self) -> &CongestionControl;
	
	#[doc(hidden)]
	#[inline(always)]
	fn congestion_control_mutable_reference(&mut self) -> &mut CongestionControl;
}
