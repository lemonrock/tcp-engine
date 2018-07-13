// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct CongestionControl
{
	initial_congestion_window_algorithm: InitialCongestionWindowAlgorithm,
	
	number_of_duplicate_acknowledgments_received_since_SND_UNA_advanced: u64,
	
	pub(crate) last_sent_data_at: MonotonicMillisecondTimestamp,
	
	// Named as per RFC 3465 Section 2.1.
	//
	// Known as 'Appropriate Byte Counting (ABC)'.
	bytes_acked: u32,
	
	// RFC 5681 Section 2: "CONGESTION WINDOW (cwnd):  A TCP state variable that limits the amount of data a TCP can send.
	// At any given time, a TCP MUST NOT send data with a sequence number higher than the sum of the highest acknowledged sequence number and the minimum of cwnd and rwnd".
	cwnd: u32,
	
	// RFC 5681 Section 2: "FLIGHT SIZE: The amount of data that has been sent but not yet cumulatively acknowledged".
	FlightSize: u32,
	
	// RFC 5681: Section 3.1: "... the slow start threshold (ssthresh), is used to determine whether the slow start or congestion avoidance algorithm is used to control data transmission ..."
	ssthresh: u32,
	
	// RFC 5681 Section 2: "Sender Maximum Segment Size (SMSS)".
	//
	// This changes after the initial SYN has been sent, as the value reflects the use of options.
	sender_maximum_segment_size: u16,
	
//	snd_recover: WrappingSequenceNumber,
//	congestion_recovery: CongestionRecovery,
//	TF_WASFRECOVERY: bool, // was in NewReno Fast Recovery
//	TF_WASCRECOVERY: bool, // was in congestion recovery
}

impl CongestionControl
{
	#[inline(always)]
	pub(crate) fn new(initial_congestion_window_algorithm: InitialCongestionWindowAlgorithm, last_acknowledgment_occurred_at: MonotonicMillisecondTimestamp, sender_maximum_segment_size: u16, cached_congestion_data: &CachedCongestionData) -> Self
	{
		let IW = initial_congestion_window_algorithm.compute_initial_window(sender_maximum_segment_size);
		
		Self
		{
			initial_congestion_window_algorithm,
			number_of_duplicate_acknowledgments_received_since_SND_UNA_advanced: 0,
			last_sent_data_at: last_acknowledgment_occurred_at,
			bytes_acked: 0,
			cwnd: IW,
			FlightSize: 0,
			ssthresh: cached_congestion_data.ssthresh(sender_maximum_segment_size),
			sender_maximum_segment_size,
		}
	}
	
	#[inline(always)]
	pub(crate) fn congestion_window_is_one(&self) -> bool
	{
		self.cwnd <= self.sender_maximum_segment_size
	}
	
	// TODO: See also RFC 6582 New Reno: https://tools.ietf.org/html/rfc6582; this is a modification to fast retransmit / Fast Recovery.
	#[inline(always)]
	pub(crate) fn bytes_sent_in_payload_in_a_segment_which_is_not_a_zero_window_probe_or_retransmission(&mut self, increase_flight_size_by_amount_of_bytes: u32)
	{
		self.FlightSize += increase_flight_size_by_amount_of_bytes
	}
	
	#[inline(always)]
	pub(crate) fn increase_bytes_acknowledged(&mut self, decrease_flight_size_by_amount_of_bytes: u32)
	{
		self.FlightSize -= decrease_flight_size_by_amount_of_bytes;
		
		/// RFC 5681 Section 3.1: "The slow start algorithm is used when cwnd < ssthresh, while the congestion avoidance algorithm is used when cwnd > ssthresh.
		/// When cwnd and ssthresh are equal, the sender may use either slow start or congestion avoidance".
		if self.congestion_window() <= self.ssthresh
		{
			self.increase_bytes_acknowledged_slow_start(decrease_flight_size_by_amount_of_bytes)
		}
		else
		{
			self.increase_bytes_acknowledged_congestion_avoidance(decrease_flight_size_by_amount_of_bytes)
		}
	}
	
	/// RFC 5681: "... N is the number of previously unacknowledged bytes acknowledged in the incoming ACK".
	fn increase_bytes_acknowledged_slow_start(&mut self, N: u32)
	{
		// RFC 5681 Section 7 Paragraph 5: "During slow start, the usage of Appropriate Byte Counting (RFC 3465) with L=1*SMSS is explicitly recommended".
		{
			// RFC 3465 Section 2.3: "The limit, L, chosen for the cwnd increase during slow start, controls the aggressiveness of the algorithm".
			let L = self.sender_maximum_segment_size;
			
			let clamped_maxium_number_of_bytes = max(by_amount_of_bytes, L);
			
			self.bytes_acked += clamped_maxium_number_of_bytes;
			
			// RFC 3465 Section 2.1: "When bytes_acked becomes greater than or equal to the value of the congestion window, bytes_acked is reduced by the value of cwnd".
			if self.bytes_acked >= self.congestion_window()
			{
				self.bytes_acked -= self.congestion_window()
			}
		}
		// RFC 3465 Section 2.1: "Next, cwnd is incremented by a full-sized segment (SMSS)".
		// RFC 5681 Section 3.1: "... we RECOMMEND that TCP implementations increase cwnd, per: cwnd += min (N, SMSS) where N is the number of previously unacknowledged bytes acknowledged in the incoming ACK".
		self.increment_congestion_window(min(N, self.sender_maximum_segment_size))
	}
	
	fn increase_bytes_acknowledged_congestion_avoidance(&mut self, N: u32)
	{
// TODO: double-check this methodology.
		xxx;

//		let clamped_maxium_number_of_bytes = min(N, self.sender_maximum_segment_size);
//		self.bytes_acked += clamped_maxium_number_of_bytes;
//
//		// RFC 5681: "When the number of bytes acknowledged reaches cwnd, then cwnd can be incremented by up to SMSS bytes.
//		// Note that during congestion avoidance, cwnd MUST NOT be increased by more than SMSS bytes per RTT".
//		//
//		// RFC 3465 Section 2.1: "When bytes_acked becomes greater than or equal to the value of the congestion window, bytes_acked is reduced by the value of cwnd
//		// ...
//		// Next, cwnd is incremented by a full-sized segment (SMSS)".
//		if self.bytes_acked >= self.cwnd
//		{
//			self.bytes_acked -= self.cwnd;
//			self.cwnd += self.sender_maximum_segment_size
//		}


//		let increment = ((self.sender_maximum_segment_size as u32) * (self.sender_maximum_segment_size as u32)) / self.cwnd;
//		self.cwnd += if increment == 0
//		{
//			1
//		}
//		else
//		{
//			increment
//		};
	}
	
	/// RFC 5681 Section 3.1 Page 7: "When a TCP sender detects segment loss using the retransmission timer and the given segment has not yet been resent by way of the retransmission timer, the value of ssthresh MUST be set to no more than the value given in equation (4): ssthresh = max (FlightSize / 2, 2*SMSS) where ... FlightSize is the amount of outstanding data in the network".
	///
	/// RFC 5681 Section 7 Paragraph 6: "...  ssthresh must be set to half the FlightSize on the first retransmission of a given segment and then is held constant on subsequent retransmissions of the same segment".
	#[inline(always)]
	pub(crate) fn rfc_5681_section_7_paragaph_6_set_ssthresh_to_half_of_flight_size_on_first_retransmission(&mut self)
	{
		self.ssthresh = max(self.FlightSize / 2, 2 * self.sender_maximum_segment_size)
	}
	
	/// RFC 5681 Section 2: "At any given time, a TCP MUST NOT send data with a sequence number higher than the sum of the highest acknowledged sequence number and the minimum of cwnd and rwnd".
	#[inline(always)]
	pub(crate) fn maximum_data(&self, rwnd: u32) -> u32
	{
		min(self.congestion_window(), rwnd)
	}
	
	/// RFC 5681 Section 2: "At any given time, a TCP MUST NOT send data with a sequence number higher than the sum of the highest acknowledged sequence number and the minimum of cwnd and rwnd".
	#[inline(always)]
	fn maximum_sequence_number(&self, SND: &TransmissionControlBlockSend) -> WrappingSequenceNumber
	{
		// RFC 5681 Section 2: "RECEIVER WINDOW (rwnd): The most recently advertised receiver window".
		SND.UNA_less_one() + min(self.congestion_window(), SND.rwnd())
	}
	
	/// RFC 5681 Section 3.2 Paragraph 2: "... duplicate ACKs (as defined in section 2, without any intervening ACKs which move SND.UNA)".
	#[inline(always)]
	pub(crate) fn increment_duplicate_acknowledgments_received_without_any_intervening_acknwoledgments_which_moved_SND_UNA(&mut self)
	{
		self.number_of_duplicate_acknowledgments_received_since_SND_UNA_advanced += 1;
	}
	
	/// RFC 5681 Section 5.2 Paragraph 2 implies acknowledgments which DO move SND.UNA reset the duplicate acknowledgments count.
	#[inline(always)]
	pub(crate) fn reset_duplicate_acknowledgment_count(&mut self)
	{
		self.number_of_duplicate_acknowledgments_received_since_SND_UNA_advanced = 0;
	}
	
	#[inline(always)]
	pub(crate) fn last_sent_data_at(&mut self, now: MonotonicMillisecondTimestamp)
	{
		self.last_sent_data_at = now
	}
	
	/// RFC 5681 Section 4.1: "When TCP has not received a segment for more than one retransmission timeout, cwnd is reduced to the value of the restart window (RW) before transmission begins
	/// ...
	/// TCP SHOULD set cwnd to no more than RW (the restart window) before beginning transmission if the TCP has not sent data in an interval exceeding the retransmission timeout".
	#[inline(always)]
	pub(crate) fn reset_congestion_window_to_restart_window_if_no_data_sent_for_an_interval_exceeding_the_retransmission_time_out(&mut self, explicit_congestion_notification_state: Option<&mut ExplicitCongestionNotificationState>, now: MonotonicMillisecondTimestamp, retransmission_time_out: MillisecondDuration)
	{
		debug_assert!(self.last_sent_data_at >= now, "self.last_sent_data_at '{}' is less than now '{}'", self.last_sent_data_at, now);
		
		if (self.last_sent_data_at - now) > retransmission_time_out
		{
			self.reset_congestion_window_to_restart_window(explicit_congestion_notification_state);
		}
	}
	
	/// RFC 5681 Section 3.1 Page 8 Paragraph 2: "Furthermore, upon a timeout cwnd MUST be set to no more than the loss window, LW, which equals 1 full-sized segment (regardless of the value of IW).
	/// Therefore, after retransmitting the dropped segment the TCP sender uses the slow start algorithm to increase the window from 1 full-sized segment to the new value of ssthresh, at which point congestion avoidance again takes over".
	pub(crate) fn reset_congestion_window_to_loss_window_because_retransmission_timed_out(&mut self, explicit_congestion_notification_state: Option<&mut ExplicitCongestionNotificationState>)
	{
		self.reset_congestion_window_to_loss_window(explicit_congestion_notification_state);
	}
	
	#[inline(always)]
	pub(crate) fn recalculate_sender_maximum_segment_size_when_entering_established_state(&mut self, negotiated_maximum_segment_size: u16, timestamps_in_use: bool, md5_signatures_in_use: bool, selective_acknowledgments_in_use: bool)
	{
		self.sender_maximum_segment_size = Self::calculate_sender_maximum_segment_size_in_synchronized_state(negotiated_maximum_segment_size, timestamps_in_use, md5_signatures_in_use, selective_acknowledgments_in_use)
	}
	
	#[inline(always)]
	pub(crate) fn calculate_sender_maximum_segment_size_in_non_synchronized_state(negotiated_maximum_segment_size: u16, timestamps_in_use: bool, md5_signatures_in_use: bool, selective_acknowledgments_permitted_in_use: bool, maximum_segment_size_in_use: bool, window_scale_in_use: bool) -> u16
	{
		let mut options_size = if timestamps_in_use
		{
			TimestampsOption::KnownLength
		}
		else
		{
			0
		};
		
		if md5_signatures_in_use
		{
			options_size += AuthenticationOption::Md5SignatureOptionKnownLength;
		}
		
		if selective_acknowledgments_permitted_in_use
		{
			options_size += SelectiveAcknowledgmentPermittedOptionKnownLength::OneBlockLength;
		}
		
		if maximum_segment_size_in_use
		{
			options_size += MaximumSegmentSizeOption::KnownLength;
		}
		
		if window_scale_in_use
		{
			options_size += WindowScaleOption::KnownLength;
		}
		
		negotiated_maximum_segment_size - (TcpSegment::round_up_options_size_to_multiple_of_four(options_size) as u16)
	}
	
	#[inline(always)]
	pub(crate) fn calculate_sender_maximum_segment_size_in_synchronized_state(negotiated_maximum_segment_size: u16, timestamps_in_use: bool, md5_signatures_in_use: bool, selective_acknowledgments_in_use: bool) -> u16
	{
		let mut options_size = if timestamps_in_use
		{
			TimestampsOption::KnownLength
		} else {
			0
		};
		
		if md5_signatures_in_use
		{
			options_size += AuthenticationOption::Md5SignatureOptionKnownLength;
		}
		
		if selective_acknowledgments_in_use
		{
			options_size += SelectiveAcknowledgmentOption::OneBlockLength;
		}
		
		negotiated_maximum_segment_size - (TcpSegment::round_up_options_size_to_multiple_of_four(options_size) as u16)
	}
}

/// Congestion window manipulation.
impl CongestionControl
{
	#[inline(always)]
	fn reset_congestion_window_to_restart_window(&mut self, explicit_congestion_notification_state: Option<&mut ExplicitCongestionNotificationState>)
	{
		self.set_congestion_window(self.restart_window(), explicit_congestion_notification_state)
	}
	
	#[inline(always)]
	fn reset_congestion_window_to_loss_window(&mut self, explicit_congestion_notification_state: Option<&mut ExplicitCongestionNotificationState>)
	{
		self.set_congestion_window(self.loss_window(), explicit_congestion_notification_state)
	}
	
	/// RFC 5681 Section 2: "RESTART WINDOW (RW): The restart window is the size of the congestion window (cwnd) after a TCP restarts transmission after an idle period (if the slow start algorithm is used ...)".
	///
	/// RFC 5681 Section 4.1: "For the purposes of this standard, we define RW = min(IW,cwnd)".
	#[inline(always)]
	fn restart_window(&self) -> u32
	{
		let IW = self.initial_congestion_window_algorithm.compute_initial_window(self.sender_maximum_segment_size);
		
		min(IW, self.congestion_window())
	}
	
	/// RFC 5681 Section 2: "LOSS WINDOW (LW): The loss window is the size of the congestion window after a TCP sender detects loss using its retransmission timer".
	///
	/// RFC 5681 Section 3.1 Page 8 Paragraph 2: "... the loss window, LW, ... equals 1 full-sized segment (regardless of the value of IW)".
	#[inline(always)]
	fn loss_window(&self) -> u32
	{
		self.sender_maximum_segment_size as u32
	}
	
	/// RFC 5681 Section 2: "INITIAL WINDOW (IW): The initial window is the size of the sender's congestion window after the three-way handshake is completed".
	#[inline(always)]
	fn initial_window(&self) -> u32
	{
		self.initial_congestion_window_algorithm.compute_initial_window(self.sender_maximum_segment_size)
	}
	
	#[inline(always)]
	fn increment_congestion_window(&mut self, increment: u32)
	{
		self.cwnd = self.cwnd.saturating_add(increment)
	}
	
	#[inline(always)]
	fn set_congestion_window(&mut self, value: u32, explicit_congestion_notification_state: Option<&mut ExplicitCongestionNotificationState>)
	{
		if value > self.cwnd
		{
			if let Some(explicit_congestion_notification_state) = explicit_congestion_notification_state
			{
				explicit_congestion_notification_state.reduced_congestion_window();
			}
		}
		self.cwnd = value
	}
	
	#[inline(always)]
	fn congestion_window(&self) -> u32
	{
		self.cwnd
	}
}
