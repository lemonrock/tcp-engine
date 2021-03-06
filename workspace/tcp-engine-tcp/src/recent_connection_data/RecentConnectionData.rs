// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Recent connection data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecentConnectionData
{
	/// `SRTT`.
	smoothed_round_trip_time: MillisecondDuration,
	
	/// `RTTVAR`.
	round_trip_time_variance: MillisecondDuration,
	
	/// RFC 5681: Section 3.1: "... the slow start threshold (ssthresh), is used to determine whether the slow start or congestion avoidance algorithm is used to control data transmission ..."
	ssthresh: u32,
}

impl Default for RecentConnectionData
{
	#[inline(always)]
	fn default() -> Self
	{
		Self::Default
	}
}

impl RecentConnectionData
{
	const Default: Self = Self
	{
		smoothed_round_trip_time: RetransmissionTimeOutData::InitialSmoothedRoundTripTime,
		
		round_trip_time_variance: RetransmissionTimeOutData::InitialRoundTripTimeVariance,
		
		// RFC 5681: Section 3.1: "The initial value of ssthresh SHOULD be set arbitrarily high (e.g., to the size of the largest possible advertised window)".
		ssthresh: WindowSize::Maximum.value(),
	};
	
	/// Creates a new instance.
	#[inline(always)]
	pub fn new(&self, smoothed_round_trip_time: MillisecondDuration, round_trip_time_variance: MillisecondDuration, ssthresh: u32) -> RecentConnectionData
	{
		Self
		{
			smoothed_round_trip_time,
			round_trip_time_variance,
			ssthresh,
		}
	}
	
	/// `SRTT` and `RTTVAR`.
	#[inline(always)]
	pub fn retransmission_time_out_data(&self, is_for_non_synchronized_state: bool) -> RetransmissionTimeOutData
	{
		RetransmissionTimeOutData::new(self.smoothed_round_trip_time, self.round_trip_time_variance, is_for_non_synchronized_state)
	}
	
	/// RFC 5681: Section 3.1: "... the slow start threshold (ssthresh), is used to determine whether the slow start or congestion avoidance algorithm is used to control data transmission ..."
	#[inline(always)]
	pub fn ssthresh(&self, sender_maximum_segment_size: u32) -> u32
	{
		max(2 * sender_maximum_segment_size, self.ssthresh)
	}
	
	#[inline(always)]
	pub(crate) fn update(&mut self, recent_connection_data_from_transmission_control_block: Self)
	{
		self.update_retransmission_time_out(recent_connection_data_from_transmission_control_block.smoothed_round_trip_time, recent_connection_data_from_transmission_control_block.round_trip_time_variance);
		self.update_ssthresh(recent_connection_data_from_transmission_control_block.ssthresh)
	}
	
	#[inline(always)]
	fn update_retransmission_time_out(&mut self, smoothed_round_trip_time: MillisecondDuration, round_trip_time_variance: MillisecondDuration)
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
	fn update_ssthresh(&mut self, ssthresh: u32)
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
