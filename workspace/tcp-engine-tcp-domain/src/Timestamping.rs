// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Timestamping.
#[derive(Debug)]
pub struct Timestamping
{
	our_offset: u32,
	
	/// RFC 7323, Section 4.3: "TS.Recent holds a timestamp to be echoed in TSecr whenever a segment is sent".
	TS_Recent: NetworkEndianU32,

	/// RFC 7323, Section 4.3: " Last.ACK.sent holds the ACK field from the last segment sent
	/// Last.ACK.sent will equal RCV.NXT except when <ACK>s have been delayed".
	Last_ACK_sent: WrappingSequenceNumber,
}

impl Timestamping
{
	/// RFC 7323, Section 5.3, Point R1: "SEG.TSval < TS.Recent".
	pub fn is_TS_Recent_greater_than(&self, SEG_TSval: NetworkEndianU32) -> bool
	{
		WrappingTimestamp::from(SEG_TSval) < WrappingTimestamp::from(self.TS_Recent)
	}
	
	/// The definition of TS.Recent being invalid is in RFC 7323, Section 5.5: "We therefore require that an implementation of PAWS include a mechanism to "invalidate" the TS.Recent value when a connection is idle for more than 24 days. An alternative solution to the problem of outdated timestamps would be to send keep-alive segments at a very low rate, but still more often than the wrap-around time for timestamps, e.g., once a day".
	///
	/// Since we do not, through our keep-alive logic, permit a connection to be idle for more than 24 days, TS.Recent will always be valid.
	#[inline(always)]
	pub fn is_TS_Recent_valid(&self) -> bool
	{
		true
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn set_TS_Recent(&mut self, SEG_TSval: NetworkEndianU32)
	{
		self.TS_Recent = SEG_TSval
	}
	
	/// RFC 7323, Section 4.3 (2): "If SEG.TSval >= TS.Recent and SEG.SEQ <= Last.ACK.sent then SEG.TSval is copied to TS.Recent; otherwise, it is ignored".
	/// RFC 7323, Section 5.3, Point R3: "If an arriving segment satisfies SEG.TSval >= TS.Recent and SEG.SEQ <= Last.ACK.sent (see Section 4.3), then record its timestamp in TS.Recent.
	#[inline(always)]
	pub fn update_TS_Recent_if_appropriate(&mut self, SEG_TSval: NetworkEndianU32, SEG_SEQ: WrappingSequenceNumber)
	{
		if WrappingTimestamp::from(SEG_TSval) >= WrappingTimestamp::from(self.TS_Recent) && SEG_SEQ <= self.Last_ACK_sent
		{
			self.set_TS_Recent(SEG_TSval)
		}
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn update_Last_ACK_sent(&mut self, Last_ACK_sent: WrappingSequenceNumber)
	{
		self.Last_ACK_sent = Last_ACK_sent;
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn synflood_synchronize_acknowledgment_timestamps_option(now: MonotonicMillisecondTimestamp, their_timestamp_value: NetworkEndianU32) -> TimestampsOption
	{
		let TSval = Self::our_initial_timestamp(now);
		
		let TSecr = their_timestamp_value;
		
		TimestampsOption::from_TSval_and_TSecr(TSval, TSecr)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn normal_timestamps_option(&self, now: MonotonicMillisecondTimestamp) -> TimestampsOption
	{
		let TSval = self.our_subsequent_timestamp(now);
		
		// RFC 7323, Section 4.3 (3):  When a TSopt is sent, its TSecr field is set to the current TS.Recent value".
		let TSecr = self.TS_Recent;
		
		TimestampsOption::from_TSval_and_TSecr(TSval, TSecr)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn new_for_closed_to_synchronize_sent() -> Option<Self>
	{
		Some
		(
			Self
			{
				our_offset: generate_hyper_thread_safe_random_u32(),
				TS_Recent: NetworkEndianU32::Zero,
				Last_ACK_sent: WrappingSequenceNumber::Zero,
			}
		)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn new_for_sychronize_received_to_established(tcp_options: &TcpOptions, now: MonotonicMillisecondTimestamp, RCV_NXT: WrappingSequenceNumber) -> Option<Self>
	{
		if let Some(timestamps) = tcp_options.timestamps.as_ref()
		{
			let our_timestamp = timestamps.TSecr.to_native_endian();
			let now_u32: u32 = now.into();
			let approximate_original_timestamp_offset = now_u32.wrapping_sub(our_timestamp);
			Some
			(
				Self
				{
					our_offset: approximate_original_timestamp_offset,
					TS_Recent: timestamps.TSval,
					
					// RFC 7323 Section 4.3 (1): "Last.ACK.sent will equal RCV.NXT ..."
					Last_ACK_sent: RCV_NXT,
				}
			)
		}
		else
		{
			None
		}
	}
	
	/// RFC 7323, Section 4.1: "The difference between a received TSecr value and the current timestamp clock value provides an RTT measurement".
	#[inline(always)]
	pub fn measurement_of_round_trip_time(&self, now: MonotonicMillisecondTimestamp, timestamps_option: &TimestampsOption) -> Option<MillisecondDuration>
	{
		let TSecr = timestamps_option.TSecr.to_native_endian();
		
		let now_u32: u32 = now.into();
		let real_time_stamp = WrappingTimestamp::from(TSecr.wrapping_sub(self.our_offset));
		let relative_difference = WrappingTimestamp::from(now_u32).relative_difference(real_time_stamp);
		
		if likely!(relative_difference >= 0)
		{
			let round_trip_time = MillisecondDuration::from_milliseconds(relative_difference as u32 as u64);
			Some(round_trip_time)
		}
		else
		{
			None
		}
	}
	
	/// "TSval".
	#[inline(always)]
	fn our_initial_timestamp(now: MonotonicMillisecondTimestamp) -> NetworkEndianU32
	{
		Self::our_timestamp(now, generate_hyper_thread_safe_random_u32())
	}
	
	/// "TSval".
	#[inline(always)]
	fn our_subsequent_timestamp(&self, now: MonotonicMillisecondTimestamp) -> NetworkEndianU32
	{
		Self::our_timestamp(now, self.our_offset)
	}
	
	/// "TSval".
	#[inline(always)]
	fn our_timestamp(now: MonotonicMillisecondTimestamp, our_offset: u32) -> NetworkEndianU32
	{
		let now_u32: u32 = now.into();
		let timestamp = now_u32.wrapping_add(our_offset);
		NetworkEndianU32::from_native_endian(timestamp)
	}
}
