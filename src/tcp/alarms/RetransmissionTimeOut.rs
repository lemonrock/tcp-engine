// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Maintains the state of the retransmission time out timer.
///
/// * Calculates according to RFC 6298
/// * Resets the interpretation of the measurement of round-trip times once a threshold of back off doubling is reached (MaximumNumberOfBackOffsBeforeResettingMeasurements).
///
/// This logic is based on RFC 6298, which obsoleted RFC 2988 (which itself clarified RFC 1122 and RFC 793 and complemented RFC 2581).
///
/// In practice, RFC 6298 is extremely similar to RFC 2988.
///
/// This timer is used with congestion control; see RFC 5681 (which itself obsoletes RFC 2581).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct RetransmissionTimeOut
{
	/// `SRTT`.
	smoothed_round_trip_time: MillisecondDuration,
	
	/// `RTTVAR`.
	round_trip_time_variance: MillisecondDuration,
	
	/// `RTO`.
	retransmission_time_out: MillisecondDuration,
	
	round_trip_time_needs_measuring: bool,

	number_of_back_offs: u8,
}

impl Default for RetransmissionTimeOut
{
	#[inline(always)]
	fn default() -> Self
	{
		Self::Default
	}
}

impl RetransmissionTimeOut
{
	const Default: Self = Self
	{
		smoothed_round_trip_time: MillisecondDuration::Zero,
		round_trip_time_variance: MillisecondDuration::Zero,
		retransmission_time_out: Self::clamped_retransmission_time_out(Self::InitialRetransmissionTimeOut),
		round_trip_time_needs_measuring: true,
		number_of_back_offs: 0,
	};
	
	const ClockGranularity: MillisecondDuration = MillisecondDuration::from_milliseconds(Tick::MillisecondsPerTick);
	
	/// NOTE: We VIOLATE RFC 6298 Section 2.4 here ("Whenever RTO is computed, if it is less than 1 second then the RTO SHOULD be rounded up to 1 second.") by choosing a minimum of 256 milliseconds.
	///
	/// This is more inline with modern TCP stacks; Linux also defaults to 200ms, for instance.
	const MinimumRetransmissionTimeOut: MillisecondDuration = MillisecondDuration::from_milliseconds(256);
	
	/// RFC 6298 Section 2.4 here ("A maximum value MAY be placed on RTO provided it is at least 60 seconds").
	const MaximumRetransmissionTimeOut: MillisecondDuration = MillisecondDuration::from_tick_duration(AlarmWheel::InclusiveMaximumGoesOffInTicks);
	
	// RFC 6298 Section 2.1" "Until a round-trip time (RTT) measurement has been made for a segment sent between the sender and receiver, the sender SHOULD set RTO <- 1 second, though the "backing off" on repeated retransmission discussed in (5.5) still applies.
	// RFC 2988 Section 2.1: "Until a round-trip time (RTT) measurement has been made for a segment sent between the sender and receiver, the sender SHOULD set RTO <- 3 seconds (per RFC 1122 [Bra89]), though the "backing off" on repeated retransmission discussed in (5.5) still applies".
	const InitialRetransmissionTimeOut: MilliseconDuration = MillisecondDuration::OneSecond;
	
	const MaximumNumberOfBackOffsBeforeResettingMeasurements: u8 = 8;
	
	#[inline(always)]
	pub(crate) fn average_with(&mut self, other: &Self)
	{
		if other.round_trip_time_needs_measuring
		{
			return
		}
		
		if self.round_trip_time_needs_measuring
		{
			self.smoothed_round_trip_time = other.smoothed_round_trip_time;
			self.round_trip_time_variance = other.round_trip_time_variance;
			self.retransmission_time_out = other.retransmission_time_out;
			self.round_trip_time_needs_measuring = false;
			self.number_of_back_offs = other.number_of_back_offs;
			return
		}
		
		// number of backs should be used as a weighting; the more back-offs, the less reliable the samples (RFC 6298 Section 5, final paragraph).
		// + 1 as number of back-offs can be zero.
		let right_numerator = self.number_of_back_offs + 1;
		let left_numerator = other.number_of_back_offs + 1;
		let average_divisor = right_numerator + other.number_of_back_offs + 1;
		
		self.smoothed_round_trip_time = ((left_numerator * self.smoothed_round_trip_time) + (right_numerator * other.smoothed_round_trip_time)) / average_divisor;
		self.round_trip_time_variance = ((left_numerator * self.round_trip_time_variance) + (right_numerator * other.round_trip_time_variance)) / average_divisor;
		self.recompute_retransmission_time_out();
		self.number_of_back_offs = 0;
	}
	
	#[inline(always)]
	pub(crate) fn time_out(&self) -> MillisecondDuration
	{
		self.retransmission_time_out
	}
	
	/// RFC 6298 Section 5.5: "back off the timer"
	#[inline(always)]
	pub(crate) fn back_off_after_expiry_of_retransmission_alarm(&mut self)
	{
		// RFC 6298 Section 5, final paragraph:-
		// "Note that a TCP implementation MAY clear SRTT and RTTVAR after backing off the timer multiple times as it is likely that the current SRTT and RTTVAR are bogus in this situation.
		// Once SRTT and RTTVAR are cleared, they should be initialized with the next RTT sample taken per (2.2) rather than using (2.3)."
		if self.number_of_back_offs == Self::MaximumNumberOfBackOffsBeforeResettingMeasurements
		{
			self.number_of_back_offs == 0;
		}
		else
		{
			self.number_of_back_offs += 1;
		}
		
		let backed_off = self.retransmission_time_out * 2;
		self.retransmission_time_out = if backed_off > Self::MaximumRetransmissionTimeOut
		{
			Self::MaximumRetransmissionTimeOut
		}
		else
		{
			backed_off
		};
	}
	
	/// RFC 6298 Section 5.7: "If the timer expires awaiting the ACK of a SYN segment and the TCP implementation is using an RTO less than 3 seconds, the RTO MUST be re-initialized to 3 seconds when data transmission begins (i.e., after the three-way handshake completes)."
	#[inline(always)]
	pub(crate) fn reset_after_establishment_of_state_if_we_sent_the_first_synchronize_segment_and_the_timer_expired(&mut self, alarm_expired_awaiting_synchronize_acknowledgment: bool)
	{
		if alarm_expired_awaiting_synchronize_acknowledgment
		{
			if Self::InitialRetransmissionTimeOut < MillisecondDuration::ThreeSeconds
			{
				self.retransmission_time_out = MillisecondDuration::ThreeSeconds;
				self.number_of_back_offs = 0
			}
		}
	}
	
	#[inline(always)]
	pub(crate) fn process_measurement_of_round_trip_time(&mut self, measurement_of_round_trip_time: MillisecondDuration)
	{
		if self.round_trip_time_needs_measuring
		{
			self.first_measurement_of_round_trip_time_made(measurement_of_round_trip_time);
		}
		else
		{
			self.subsequent_measurement_of_round_trip_time(measurement_of_round_trip_time);
		}
		self.number_of_back_offs = 0;
	}
	
	/// RFC 6298 Section 2.2 & RFC 2988 Section 2.2: "When the first RTT measurement R is made, the host MUST set
	/// SRTT <- R
	/// RTTVAR <- R/2
	/// RTO <- SRTT + max (G, K*RTTVAR)
	/// where K = 4.
	/// ".
	#[inline(always)]
	fn first_measurement_of_round_trip_time_made(&mut self, measurement_of_round_trip_time: MillisecondDuration)
	{
		let R = measurement_of_round_trip_time;
		
		self.smoothed_round_trip_time = R;
		self.round_trip_time_variance = R / 2;
		self.recompute_retransmission_time_out();
		
		self.round_trip_time_needs_measuring = false;
	}
	
	/// RFC 6298 Section 2.3 & RFC 2988 Section 2.3: "When a subsequent RTT measurement R' is made, a host MUST set
	/// RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
	/// SRTT <- (1 - alpha) * SRTT + alpha * R'
	///
	/// The value of SRTT used in the update to RTTVAR is its value before updating SRTT itself using the second assignment.
	/// That is, updating RTTVAR and SRTT MUST be computed in the above order.
	///
	/// The above SHOULD be computed using alpha=1/8 and beta=1/4 (as suggested in JK88 (Jacobson, V. and M. Karels, Congestion Avoidance and Control)).
	///
	/// After the computation, a host MUST update RTO <- SRTT + max (G, K*RTTVAR)".
	fn subsequent_measurement_of_round_trip_time(&mut self, measurement_of_round_trip_time: MillisecondDuration)
	{
		// R'.
		let Rdash = measurement_of_round_trip_time;
		
		// Nominally, `beta` is ¼ and `1 - beta` is ¾.
		// Thus `RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'|` is actually `SRTT = ¾ * self.round_trip_time_variance + ¼ * |SRTT - R'|`; we can then multiply by 4 to get:-
		// `4 * RTTVAR = 3 * self.round_trip_time_variance + |SRTT - R'|`.
		// `RTTVAR = (3 * self.round_trip_time_variance + |SRTT - R'|) / 4`.
		// So, instead of `self.round_trip_time_variance = (1 - beta) * self.round_trip_time_variance + beta + self.smoothed_round_trip_time.absolute_difference(Rdash)`, we have:-
		self.round_trip_time_variance = (3 * self.round_trip_time_variance + self.smoothed_round_trip_time.absolute_difference(Rdash)) / 4;
		
		// Nominally, `alpha` is ¹⁄₈ and `1 - alpha` is ⁷⁄₈
		// Thus, `SRTT = (1 - alpha) * SRTT + alpha * R'` is actually `SRTT = ⁷⁄₈ * SRTT + ¹⁄₈ * R'`; we can then multiply by 8 to get:-
		// `8 * SRTT = 7 * SRTT + R'` .
		// `SRTT = (7 * SRTT + R') / 8.
		// So, instead of `self.smoothed_round_trip_time = (1 - alpha) * self.smoothed_round_trip_time + alpha * Rdash`, we have:-
		self.smoothed_round_trip_time = (7 * self.smoothed_round_trip_time + Rdash) / 8;
		
		self.recompute_retransmission_time_out();
	}
	
	#[inline(always)]
	fn recompute_retransmission_time_out(&mut self)
	{
		// Clock granularity of `G` milliseconds.
		const G: MillisecondDuration = Self::ClockGranularity;
		
		const K: u64 = 4;
		
		self.retransmission_time_out = Self::clamped_retransmission_time_out(self.smoothed_round_trip_time.saturating_add(max(G, self.round_trip_time_variance * K)));
	}
	
	#[inline(always)]
	fn clamped_retransmission_time_out(unclamped_retransmission_time_out: MillisecondDuration) -> MillisecondDuration
	{
		let clamped = if unclamped_retransmission_time_out < Self::MinimumRetransmissionTimeOut
		{
			Self::MinimumRetransmissionTimeOut
		}
		else if unclamped_retransmission_time_out > Self::MaximumRetransmissionTimeOut
		{
			Self::MaximumRetransmissionTimeOut
		}
		else
		{
			unclamped_retransmission_time_out
		};
	}
}
