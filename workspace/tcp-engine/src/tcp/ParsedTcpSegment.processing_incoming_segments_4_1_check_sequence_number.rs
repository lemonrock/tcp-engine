// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


macro_rules! check_sequence_number_segment_is_unacceptable
{
	($self: ident, $transmission_control_block: ident, $reason: expr) =>
	{
		{
			if $self.reset_flag_unset()
			{
				$self.interface.send_acknowledgment($self.reuse_packet(), $transmission_control_block, $self.now, Flags::Acknowledgment, $transmission_control_block.SND.NXT(), $transmission_control_block.RCV.NXT());
			}
			invalid!($self, $reason)
		}
	}
}

/// Processing Incoming Segments 4.1.1: RFC 7323, Section 5.3, Point R1.
macro_rules! processing_incoming_segments_4_1_1_r1
{
	($self: ident, $transmission_control_block: ident, $timestamping: ident, $timestamps_option: ident) =>
	{
		{
			let SEG_TSval = $timestamps_option.TSval;
			
			if $timestamping.is_TS_Recent_greater_than(SEG_TSval) && $timestamping.is_TS_Recent_valid() && $self.reset_flag_unset()
			{
				check_sequence_number_segment_is_unacceptable!($self, $transmission_control_block, "TCP segment was not acceptable as it did not have a recent enough timestamp")
			}
			
			($timstamping, SEG_TSval)
		}
	}
}

/// Processing Incoming Segments 4.1.2: RFC 793 Page 69 / RFC 7323, Section 5.3, Point R2.
macro_rules! check_sequence_number_4_1_1_2_r2
{
	($self: ident, $transmission_control_block: ident) =>
	{
		if !$self.processing_incoming_segments_4_1_3_r2_segment_is_acceptable_because_it_occupies_a_portion_of_valid_receive_sequence_space($transmission_control_block)
		{
			check_sequence_number_segment_is_unacceptable!($self, $transmission_control_block, "TCP segment was not acceptable as it did not occupy a portion of the valid receive sequence space")
		}
	}
}

/// Processing Incoming Segments 4.1: Check sequence number.
macro_rules! processing_incoming_segments_4_1_check_sequence_number
{
	($self: ident, $transmission_control_block: ident) =>
	{
		match $transmission_control_block.timestamping_reference()
		{
			None =>
			{
				check_sequence_number_4_1_1_2_r2!($self, $transmission_control_block);
				None
			}
		
			// RFC 7323, Section 3.2: "TSopt MUST be sent in every non-<RST> segment for the duration of the connection, and SHOULD be sent in an <RST> segment".
			Some(timestamping) => match $self.tcp_options.timestamps
			{
				Some(timestamps_option) =>
				{
					let (timestamping, SEG_TSval) = processing_incoming_segments_4_1_1_r1!(self, $transmission_control_block, timestamping, timestamps_options);
					check_sequence_number_4_1_1_2_r2!($self, $transmission_control_block);
					$self.processing_incoming_segments_4_1_3_r3(SEG_TSval);
					Some(timestamps_option)
				}
				
				None => if unlikely!($self.reset_flag_set())
				{
					check_sequence_number_4_1_1_2_r2!($self, $transmission_control_block);
					None
				}
				else
				{
					invalid!($self, "TCP timestamps were negotiated; this segment, which does not have the Reset flag set, does not contain a timestamps option")
				},
			},
		}
	}
}
