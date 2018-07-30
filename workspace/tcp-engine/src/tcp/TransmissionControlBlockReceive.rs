// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct TransmissionControlBlockReceive
{
	/// RFC 793, page 25: "Next sequence number expected on an incoming segments, and is the left or lower edge of the receive window."
	///
	/// RFC 793, Glossary, page 82, expands this to call it the 'receive next sequence number': "This is the next sequence number the local TCP is expecting to receive".
	NXT: WrappingSequenceNumber,
	
	/// RFC 793, Glossary, page 82, expands this to call it the 'receive window': "This represents the sequence numbers the local (receiving) TCP is willing to receive.
	/// Thus, the local TCP considers that segments overlapping the range RCV.NXT to RCV.NXT + RCV.WND - 1 carry acceptable data or control.
	/// Segments containing sequence numbers entirely outside of this range are considered duplicates and discarded".
	///
	/// As of RFC 7323, Section 2.2 this is now the value left-shifted by `Rcv.Wind.Shift` bits.
	WND: WindowSize,
	
	/// RFC 7323, Section 2.
	Wind: Wind,
}

impl TransmissionControlBlockReceive
{
	#[inline(always)]
	pub(crate) fn new_for_closed_to_synchronize_sent() -> Self
	{
		Self
		{
			NXT: WrappingSequenceNumber::Zero,
			WND: InitialWindowSize::TrueWindow,
			Wind: Wind
			{
				Shift: InitialWindowSize::Shift
			},
		}
	}
	
	#[inline(always)]
	pub(crate) fn new_for_sychronize_received_to_established(NXT: WrappingSequenceNumber, WND: WindowSize, Wind_Shift: WindowScaleOption) -> Self
	{
		Self
		{
			NXT,
			WND,
			Wind: Wind
			{
				Shift: Wind_Shift
			},
		}
	}
	
	#[inline(always)]
	pub(crate) fn set_Wind_Shift(&mut self, window_scale_option: WindowScaleOption)
	{
		self.Wind.Shift = window_scale_option
	}
	
	// RFC 7323, Section 2.3: "The window field (SEG.WND) of every outgoing segment, with the exception of <SYN> segments, MUST be right-shifted by Rcv.Wind.Shift bits `SEG.WND = RCV.WND >> Rcv.Wind.Shift`".
	#[inline(always)]
	pub(crate) fn segment_window_size(&self) -> SegmentWindowSize
	{
		let RCV = self;
		RCV.WND >> RCV.Wind.Shift
	}
	
	#[inline(always)]
	pub(crate) fn NXT(&self) -> WrappingSequenceNumber
	{
		let RCV = self;
		RCV.NXT
	}
	
	#[inline(always)]
	pub(crate) fn initialize_NXT(&mut self, IRS: WrappingSequenceNumber)
	{
		let RCV = self;
		RCV.NXT = IRS + 1;
	}
	
	#[inline(always)]
	pub(crate) fn segment_sequence_number_exactly_matches_next_expected_sequence_number<TCBA: TransmissionControlBlockAbstractions>(&self, SEG: &ParsedTcpSegment<TCBA>) -> bool
	{
		let RCV = self;
		SEG.SEQ == RCV.NXT
	}
	
	/// RFC 5961 Section 3.2 page 8 3): "... is within the current receive window (RCV.NXT < SEG.SEQ < RCV.NXT+RCV.WND) ...".
	#[inline(always)]
	pub(crate) fn reset_is_within_window<TCBA: TransmissionControlBlockAbstractions>(&self, SEG: &ParsedTcpSegment<TCBA>) -> bool
	{
		let RCV = self;
		RCV.NXT <= SEG.SEQ && SEG.SEQ < RCV.NXT + RCV.WND
	}
	
	/// Processing Incoming Segments 4.1.3: "R2: RFC 793 Page 69".
	///
	/// RFC 793 page 25: "A segment is judged to occupy a portion of valid receive sequence space ... Due to zero windows and zero length segments, we have four cases for the acceptability of an incoming segment".
	#[inline(always)]
	pub(crate) fn processing_incoming_segments_4_1_3_r2_segment_is_acceptable_because_it_occupies_a_portion_of_valid_receive_sequence_space<TCBA: TransmissionControlBlockAbstractions>(&self, SEG: &ParsedTcpSegment<TCBA>) -> bool
	{
		let RCV = self;
		
		// Processing Incoming Segments 4.1.3 Table 4.1: Tests for Acceptability of an Incoming Segment.
		if SEG.LEN == 0
		{
			let first_inclusive_sequence_number = SEG.SEQ;
			
			if RCV.WND == WindowSize::Zero
			{
				first_inclusive_sequence_number == RCV.NXT
			}
			else
			{
				let RCV_END = RCV.NXT + RCV.WND;
				RCV.NXT <= first_inclusive_sequence_number && first_inclusive_sequence_number < RCV_END
			}
		}
		else
		{
			if RCV.WND == WindowSize::Zero
			{
				false
			}
			else
			{
				let first_inclusive_sequence_number = SEG.SEQ;
				let RCV_END = RCV.NXT + RCV.WND;
				(RCV.NXT <= first_inclusive_sequence_number && first_inclusive_sequence_number < RCV_END) ||
				{
					let last_inclusive_sequence_number = SEG.SEQ + (SEG.LEN - 1);
					(RCV.NXT <= last_inclusive_sequence_number && last_inclusive_sequence_number < RCV_END)
				}
				
			}
		}
	}
}
