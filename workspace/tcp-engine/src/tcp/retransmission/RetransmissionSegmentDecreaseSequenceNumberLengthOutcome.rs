// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
enum RetransmissionSegmentDecreaseSequenceNumberLengthOutcome
{
	/// Partial acknowledgments can occur because of TSO (transmission segmentration offload), GSO (generic segmentation offload), middleboxes that repacketize and repacketization before retransmission.
	Partial
	{
		bytes_acknowledged: u32,
	},
	
	Exact
	{
		bytes_acknowledged: u32,
	},
	
	/// This can be caused by delayed acknowledgments and stretch acknowledgments and LRO (large receive offload) or GRO (generic receive offload).
	More
	{
		bytes_acknowledged: u32,
		remaining_sequence_number_length: u32
	},
}
