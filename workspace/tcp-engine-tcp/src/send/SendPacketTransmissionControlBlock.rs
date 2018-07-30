// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Functionality required in order to be able to send TCP segments.
pub trait SendPacketTransmissionControlBlock<Address: InternetProtocolAddress>: AuthenticationTransmissionControlBlock + MaximumSegmentSizeTransmissionControlBlock<Address> + TimestampingTransmissionControlBlock<Address> + ExplicitCongestionNotificationTransmissionControlBlock
{
	/// `SND.UNA`.
	#[allow(non_snake_case)]
	#[inline(always)]
	fn SND_UNA(&self) -> WrappingSequenceNumber;
	
	/// `SND.UNA - 1`.
	#[allow(non_snake_case)]
	#[inline(always)]
	fn SND_UNA_less_one(&self) -> WrappingSequenceNumber;
	
	/// `SND.NXT`.
	#[allow(non_snake_case)]
	#[inline(always)]
	fn SND_NXT(&self) -> WrappingSequenceNumber;
	
	/// `SND.NXT += data_length_including_length_of_synchronize_and_finish_controls`.
	#[allow(non_snake_case)]
	#[inline(always)]
	fn increment_SND_NXT(&mut self, data_length_including_length_of_synchronize_and_finish_controls: u32);
	
	/// Is the send window (`SND.WND`, also known as `rwnd`) zero?
	#[inline(always)]
	fn send_window_is_zero(&self) -> bool;
	
	/// Is the send window (`SND.WND`, also known as `rwnd`) non-zero?
	#[inline(always)]
	fn send_window_is_non_zero(&self) -> bool;
	
	/// Is there data in the retransmission queue?
	#[inline(always)]
	fn has_data_unacknowledged(&self) -> bool;
	
	/// Has all data been unacknowledged (ie there is nothing in the retransmission queue).
	#[inline(always)]
	fn all_data_acknowledged(&self) -> bool;
	
	/// `RCV.NXT`.
	#[allow(non_snake_case)]
	#[inline(always)]
	fn RCV_NXT(&self) -> WrappingSequenceNumber;
	
	/// `SEG.WND` for an outgoing segment.
	#[inline(always)]
	fn receive_segment_window_size(&self) -> SegmentWindowSize;
	
	/// Add to the retransmission queue.
	#[inline(always)]
	fn transmitted(&mut self, now: MonotonicMillisecondTimestamp, starts_at: WrappingSequenceNumber, data_length_excluding_length_of_synchronize_and_finish_controls: u32, flags: Flags);
}
