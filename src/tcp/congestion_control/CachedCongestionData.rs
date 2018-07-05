// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CachedCongestionData
{
	/// `SRTT`.
	smoothed_round_trip_time: MillisecondDuration,
	
	/// `RTTVAR`.
	round_trip_time_variance: MillisecondDuration,
	
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
		smoothed_round_trip_time: RetransmissionTimeOutData::InitialSmoothedRoundTripTime,
		
		round_trip_time_variance: RetransmissionTimeOutData::InitialRoundTripTimeVariance,
		
		// RFC 5681: Section 3.1: "The initial value of ssthresh SHOULD be set arbitrarily high (e.g., to the size of the largest possible advertised window)".
		ssthresh: WindowSize::Maximum.0,
	};
	
	#[inline(always)]
	pub(crate) fn new(&self, smoothed_round_trip_time: MillisecondDuration, round_trip_time_variance: MillisecondDuration, ssthresh: u32) -> RetransmissionTimeOut
	{
		Self
		{
			smoothed_round_trip_time,
			round_trip_time_variance,
			ssthresh,
		}
	}
	
	#[inline(always)]
	pub(crate) fn retransmission_time_out_data(&self, is_for_non_synchronized_state: bool) -> RetransmissionTimeOutData
	{
		RetransmissionTimeOutData::new(self.smoothed_round_trip_time, self.round_trip_time_variance, is_for_non_synchronized_state)
	}
	
	#[inline(always)]
	pub(crate) fn ssthresh(&self, sender_maximum_segment_size: u16) -> u32
	{
		max((2 * sender_maximum_segment_size) as u32, self.ssthresh)
	}
	
	#[inline(always)]
	pub(crate) fn update_retransmission_time_out(&mut self, smoothed_round_trip_time: MillisecondDuration, round_trip_time_variance: MillisecondDuration)
	{
		if self.smoothed_round_trip_time == RetransmissionTimeOutData::InitialSmoothedRoundTripTime
		{
			self.smoothed_round_trip_time = smoothed_round_trip_time;
		}
		else
		{
			self.smoothed_round_trip_time = (self.smoothed_round_trip_time + smoothed_round_trip_time) / 2;
		}
		
		if self.round_trip_time_variance == RetransmissionTimeOutData::InitialRoundTripTimeVariance
		{
			self.round_trip_time_variance = round_trip_time_variance;
		}
		else
		{
			self.round_trip_time_variance = (self.round_trip_time_variance + round_trip_time_variance) / 2;
		}
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
