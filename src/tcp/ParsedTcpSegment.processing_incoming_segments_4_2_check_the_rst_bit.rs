// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


macro_rules! processing_incoming_segments_4_2_check_the_rst_bit
{
	($self: ident, $transmission_control_block: expr, $function: path) =>
	{
		if $self.reset_flag_set()
		{
			// RFC 5961 Section 3.2 Page 8:-
			// "In all states except SYN-SENT, all reset (RST) packets are validated by checking their SEQ-fields [sequence numbers].
			// A reset is valid if its sequence number exactly matches the next expected sequence number.
			// If the RST arrives and its sequence number field does NOT match the next expected sequence number but is within the window, then the receiver should generate a [Challenge] ACK.
			// In all other cases, where the SEQ-field does not match and is outside the window, the receiver MUST silently discard the segment."
		
			let RCV = &transmission_control_block.RCV;
			let SEG = self;
			
			let segment_sequence_number_exactly_matches_next_expected_sequence_number = SEG.SEQ == RCV.NXT;
			
			if segment_sequence_number_exactly_matches_next_expected_sequence_number
			{
				transmission_control_block.forcibly_close(self.interface);
				return
			}
			else
			{
				// `RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND`.
				let reset_is_within_window = RCV.NXT <= SEG.SEQ && SEG.SEQ < RCV.NXT + RCV.WND;
				
				if reset_is_within_window
				{
					self.interface.send_challenge_acknowledgment(self.reuse_packet(), transmission_control_block);
					return
				}
				else
				{
					invalid!(SEG, "TCP Reset received by state SynchronizeSent with unacceptable acknowledgment value")
				}
			}
			
			$function($transmission_control_block, $self.interface);
			return
		}
	}
}

/// Processing Incoming Segments 4.2: Check the RST bit.
macro_rules! processing_incoming_segments_4_2_check_the_rst_bit_established_fin_wait_1_fin_wait_2_close_wait
{
	($self: ident, $transmission_control_block: expr) =>
	{
		processing_incoming_segments_4_2_check_the_rst_bit!($self, $transmission_control_block, TransmissionControlBlock::connection_reset_established_fin_wait_1_fin_wait_2_close_wait)
	}
}

/// Processing Incoming Segments 4.2: Check the RST bit.
macro_rules! processing_incoming_segments_4_2_check_the_rst_bit_closing_last_acknowledgment_time_wait
{
	($self: ident, $transmission_control_block: expr) =>
	{
		processing_incoming_segments_4_2_check_the_rst_bit!($self, $transmission_control_block, TransmissionControlBlock::connection_reset_closing_last_acknowledgment_time_wait)
	}
}
