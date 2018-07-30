// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// The algorithm for determining the Initial Window (IW) for `cwnd`, the (sender) congestion window.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum InitialCongestionWindowAlgorithm
{
	/// Calculate as per RFC 6928.
	#[allow(non_camel_case_types)]
	RFC_6928,
	
	/// Calculate as per RFC 5681.
	#[allow(non_camel_case_types)]
	RFC_5681,
	
	/// Calculate as per RFC 3390 (which is slightly more aggresive than RFC 5681).
	#[allow(non_camel_case_types)]
	RFC_3390_as_modified_by_RFC_6928_Section_2_Final_Paragraph_of_Page_4,

	/// Calculate as per RFC 2581 (which is obsolete).
	#[allow(non_camel_case_types)]
	RFC_2581,
}

impl InitialCongestionWindowAlgorithm
{
	#[inline(always)]
	fn compute_initial_window(self, sender_maximum_segment_size: u32) -> u32
	{
		use self::InitialCongestionWindowAlgorithm::*;
		
		match self
		{
			RFC_6928 =>
			{
				// RFC 6928 Section 2 Paragraph 2: "More precisely, the upper bound for the initial window will be min (10*MSS, max (2*MSS, 14600))".
				min(10 * sender_maximum_segment_size, max(2 * sender_maximum_segment_size, 14600))
			}
			
			RFC_5681 =>
			{
				// RFC 5681 Section 3.1 Paragraphs 4 - 6: "IW, the initial value of cwnd, MUST be set using the following guidelines as an upper bound.
				//
				// If SMSS > 2190 bytes:
				//    IW = 2 * SMSS bytes and MUST NOT be more than 2 segments
				// If (SMSS > 1095 bytes) and (SMSS <= 2190 bytes):
				//    IW = 3 * SMSS bytes and MUST NOT be more than 3 segments
				// if SMSS <= 1095 bytes:
				//    IW = 4 * SMSS bytes and MUST NOT be more than 4 segments
				//
				// As specified in RFC 3390, the SYN/ACK and the acknowledgment of the SYN/ACK MUST NOT increase the size of the congestion window".
				if sender_maximum_segment_size > 2190
				{
					2 * sender_maximum_segment_size
				}
				else if sender_maximum_segment_size > 1095 && sender_maximum_segment_size <= 2190
				{
					3 * sender_maximum_segment_size
				}
				else
				{
					4 * sender_maximum_segment_size
				}
			}
			
			RFC_3390_as_modified_by_RFC_6928_Section_2_Final_Paragraph_of_Page_4 =>
			{
				// RFC 3390 Section 1 Page 2: "Equivalently, the upper bound for the initial window size is based on the MSS, as follows:
				//
				// If (MSS <= 1095 bytes)
				//    then win <= 4 * MSS;
				// If (1095 bytes < MSS < 2190 bytes)
				//    then win <= 4380;
				// If (2190 bytes <= MSS)
				//    then win <= 2 * MSS;"
				if sender_maximum_segment_size <= 1095
				{
					4 * sender_maximum_segment_size
				}
				else if 1095 < sender_maximum_segment_size && sender_maximum_segment_size < 2190
				{
					4380
				}
				else
				{
					2 * sender_maximum_segment_size
				}
			}
			
			RFC_2581 =>
			{
				// RFC 2581 Section 3.1 Page 4 Paragraph 1: " IW, the initial value of cwnd, MUST be less than or equal to 2*SMSS bytes and MUST NOT be more than 2 segments".
				2 * sender_maximum_segment_size
			}
		}
	}
}
