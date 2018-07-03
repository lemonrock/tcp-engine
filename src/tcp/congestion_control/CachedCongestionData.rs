// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CachedCongestionData
{
	retransmission_time_out: RetransmissionTimeOut,
	
	// RFC 5681: Section 3.1: "... the slow start threshold (ssthresh), is used to determine whether the slow start or congestion avoidance algorithm is used to control data transmission ..."
	ssthresh: u32,
}

impl Default for CachedCongestionData
{
	#[inline(always)]
	fn default() -> Self
	{
		Self::Default
	}
}

impl CachedCongestionData
{
	const Default: Self = Self
	{
		retransmission_time_out: RetransmissionTimeOut::Default,
		// RFC 5681: Section 3.1: "The initial value of ssthresh SHOULD be set arbitrarily high (e.g., to the size of the largest possible advertised window)".
		ssthresh: WindowSize::Maximum.0,
	};
	
	#[inline(always)]
	pub(crate) fn new(&self, retransmission_time_out: RetransmissionTimeOut, ssthresh: u32) -> RetransmissionTimeOut
	{
		Self
		{
			retransmission_time_out,
			ssthresh,
		}
	}
	
	#[inline(always)]
	pub(crate) fn retransmission_time_out(&self) -> RetransmissionTimeOut
	{
		self.retransmission_time_out.clone()
	}
	
	#[inline(always)]
	pub(crate) fn ssthresh(&self, sender_maximum_segment_size: u16) -> u32
	{
		max((2 * sender_maximum_segment_size) as u32, self.ssthresh)
	}
	
	#[inline(always)]
	pub(crate) fn update_retransmission_time_out(&mut self, retransmission_time_out: RetransmissionTimeOut)
	{
		self.retransmission_time_out.average_with(retransmission_time_out)
	}
	
	#[inline(always)]
	pub(crate) fn update_ssthresh(&mut self, ssthresh: u32)
	{
		if self.ssthresh == 0
		{
			self.ssthresh = ssthresh;
		}
		else
		{
			self.ssthresh = (self.ssthresh + ssthresh) / 2;
		}
	}
}
