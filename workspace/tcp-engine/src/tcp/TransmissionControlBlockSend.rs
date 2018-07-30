// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct TransmissionControlBlockSend
{
	/// RFC 793, page 25: "Oldest unacknowledged sequence number".
	///
	/// RFC 793, Glossary, page 81, expands this to call it the 'left sequence': "This is the next sequence number to be acknowledged by the data receiving TCP (or the lowest currently unacknowledged sequence number) and is sometimes referred to as the left edge of the send window".
	UNA: WrappingSequenceNumber,
	
	/// RFC 793, page 25: "Next sequence number to be sent".
	///
	/// RFC 793, Glossary, page 83, expands this to call it the 'send sequence': "This is the next sequence number the local (sending) TCP will use on the connection.
	/// It is initially selected from an initial sequence number curve (ISN) and is incremented for each octet of data or sequenced control transmitted".
	///
	/// RFC 4015 Section 1.1 Paragraph 3: "SND.NXT holds the segment sequence number of the next segment the TCP sender will (re-)transmit ... we define as 'SND.MAX' the segment sequence number of the next original transmit to be sent
	///
	/// The definition of SND.MAX is equivalent to the definition of 'snd_max' in [Wright, G. R. and W. R. Stevens, TCP/IP Illustrated, Volume 2 (The Implementation), Addison Wesley, January 1995]()".
	///
	/// It is worth noting that our definition of `SND.NXT` is actually the definition of `snd_max` in FreeBSD (and the above book).
	NXT: WrappingSequenceNumber,
	
	/// RFC 793, Glossary, page 83 expands this to call it the 'send window': "This represents the sequence numbers which the remote (receiving) TCP is willing to receive.
	/// It is the value of the window field specified in segments from the remote (data receiving) TCP.
	/// The range of new sequence numbers which may be emitted by a TCP lies between SND.NXT and SND.UNA + SND.WND - 1.
	/// (Retransmissions of sequence numbers between SND.UNA and SND.NXT are expected, of course)".
	///
	/// As of RFC 7323, Section 2.2 this is now the value left-shifted by `Snd.Wind.Shift` bits.
	WND: WindowSize,
	
	/// RFC 5961 Section 5.2: "A new state variable MAX.SND.WND is defined as the largest window that the local sender has ever received from its peer.
	/// This window may be scaled to a value larger than 65,535 bytes".
	MAX_SND_WND: WindowSize,
	
	WND_last_updated: MonotonicMillisecondTimestamp,
	
	/// RFC 7323, Section 2.
	Wind: Wind,
	
	/// RFC 793, Page 19: "segment sequence number used for last window update".
	///
	/// RFC 793, Page 72: "SND.WL1 records the sequence number of the last segment used to update SND.WND".
	///
	/// RFC 793, Glossary, Page 83: "segment sequence number at last window update".
	WL1: WrappingSequenceNumber,
	
	/// RFC 793, Page 19: "segment acknowledgment number used for last window update".
	///
	/// RFC 793, Page 72: "SND.WL2 records the acknowledgment number of the last segment used to update SND.WND".
	///
	/// RFC 793, Glossary, Page 83: "segment acknowledgment number at last window update".
	WL2: WrappingSequenceNumber,
	
	magic_ring_buffer: MagicRingBuffer,
	retransmission_queue: RetransmissionQueue,
}

impl TransmissionControlBlockSend
{
	#[inline(always)]
	pub(crate) fn new_for_closed_to_synchronize_sent(magic_ring_buffer: MagicRingBuffer, now: MonotonicMillisecondTimestamp, ISS: WrappingSequenceNumber) -> Self
	{
		const SND_WND: WindowSize = WindowSize::Zero;
		
		Self
		{
			UNA: ISS,
			NXT: ISS + 1,
			WND: SND_WND,
			Wind: Wind
			{
				Shift: WindowScaleOption::Zero,
			},
			WL1: WrappingSequenceNumber::Zero,
			WL2: WrappingSequenceNumber::Zero,
			MAX_SND_WND: SND_WND,
			WND_last_updated: now,
			magic_ring_buffer,
			retransmission_queue: RetransmissionQueue::default(),
		}
	}
	
	#[inline(always)]
	pub(crate) fn new_for_sychronize_received_to_established(magic_ring_buffer: MagicRingBuffer, now: MonotonicMillisecondTimestamp, ISS: WrappingSequenceNumber, IRS: WrappingSequenceNumber, SND_WND: WindowSize, SND_Wind_Shift: WindowScaleOption) -> Self
	{
		Self
		{
			UNA: ISS,
			NXT: ISS + 1,
			WND: SND_WND,
			Wind: Wind
			{
				Shift: SND_Wind_Shift,
			},
			WL1: IRS,
			WL2: ISS,
			MAX_SND_WND: SND_WND,
			WND_last_updated: now,
			magic_ring_buffer,
			retransmission_queue: RetransmissionQueue::default(),
		}
	}
	
	#[inline(always)]
	pub(crate) fn UNA(&self) -> WrappingSequenceNumber
	{
		self.UNA
	}
	
	#[inline(always)]
	pub(crate) fn UNA_less_one(&self) -> WrappingSequenceNumber
	{
		self.UNA - 1
	}
	
	#[inline(always)]
	pub(crate) fn NXT(&self) -> WrappingSequenceNumber
	{
		self.NXT
	}
	
	#[inline(always)]
	pub(crate) fn segment_acknowledgment_number_is_equal_to_the_greatest<TCBA: TransmissionControlBlockAbstractions>(&self, SEG: &ParsedTcpSegment<TCBA>) -> bool
	{
		let SND = self;
		SND.UNA == SEG.ACK
	}
	
	#[inline(always)]
	pub(crate) fn acknowledgment_is_acceptable_after_applying_rfc_5961_section_5_2_paragraph_1<TCBA: TransmissionControlBlockAbstractions>(&self, SEG: &ParsedTcpSegment<TCBA>) -> bool
	{
		let SND = self;
		
		// RFC 793 was `SND.UNA < SEG.ACK && SEG.ACK <= SND.NXT`.
		// Since RFC 5961 Section 5.2 paragraph 1 has already been applied, this test simplifies to `SND.UNA < SEG.ACK`.
		SND.UNA < SEG.ACK
	}
	
	#[inline(always)]
	pub(crate) fn set_Wind_Shift(&mut self, window_scale_option: WindowScaleOption)
	{
		self.Wind.Shift = window_scale_option
	}
	
	#[inline(always)]
	pub(crate) fn advertised_window_in_the_incoming_acknowledgment_equals_the_advertised_window_in_the_last_incoming_acknowledgment<TCBA: TransmissionControlBlockAbstractions>(&self, SEG: &ParsedTcpSegment<TCBA>) -> bool
	{
		let SND = self;
		SEG.WND << SND.Wind.Shift == SND.WND
	}
	
	/// RFC 5961 Section 3.2: "If the RST bit is set and the sequence number exactly matches the next expected sequence number (RCV.NXT), then TCP MUST reset the connection".
	#[inline(always)]
	pub(crate) fn seg_ack_equals_snd_nxt<TCBA: TransmissionControlBlockAbstractions>(&self, SEG: &ParsedTcpSegment<TCBA>) -> bool
	{
		let self = SND;
		SEG.ACK == SND.NXT
	}
	
	#[inline(always)]
	pub(crate) fn increment_NXT(&mut self, increment: u32)
	{
		let self = SND;
		SND.NXT += increment
	}
	
	// RFC 5961 Section 5.2 Paragraph 1: "The ACK value is considered acceptable only if it is in the range of ((SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT)
	// All incoming segments whose ACK value doesn't satisfy the above condition MUST be discarded and an ACK sent back".
	#[inline(always)]
	pub(crate) fn rfc_5961_section_5_2_paragraph_1<TCBA: TransmissionControlBlockAbstractions>(&self, SEG: &ParsedTcpSegment<TCBA>) -> bool
	{
		let SND = self;
		let MAX_SND_WND = self.MAX_SND_WND;
		SND.NXT.sequence_numbers_differ_by_too_much(SEG.ACK) || !((SND.UNA - MAX_SND_WND) <= SEG.ACK && SEG.ACK <= SND.NXT)
	}
	
	#[inline(always)]
	pub(crate) fn move_UNA<TCBA: TransmissionControlBlockAbstractions>(&mut self, SEG: &ParsedTcpSegment<TCBA>, explicit_congestion_echo: bool) -> (u32, Option<MonotonicMillisecondTimestamp>, bool, bool)
	{
		let SEG_ACK = SEG.ACK;
		
		let (bytes_acknowledged, unretransmitted_segment_timestamp, a_window_of_data_was_processed, explicit_congestion_echo) = self.acknowledged(SEG_ACK, explicit_congestion_echo);
		
		let SND = self;
		SND.UNA = SEG_ACK;
		
		(bytes_acknowledged, unretransmitted_segment_timestamp, a_window_of_data_was_processed, explicit_congestion_echo)
	}
	
	#[inline(always)]
	pub(crate) fn set_window<TCBA: TransmissionControlBlockAbstractions>(&mut self, SEG: &ParsedTcpSegment<TCBA>, now: MonotonicMillisecondTimestamp)
	{
		let SND = self;
		
		let MAX_SND_WND = self.MAX_SND_WND;
		
		// RFC 7323 Section 2.3: "The window field (SEG.WND) in the header of every incoming segment, with the exception of <SYN> segments, MUST be left-shifted by Snd.Wind.Shift bits before updating SND.WND:
		// SND.WND = SEG.WND << Snd.Wind.Shift
		// (assuming the other conditions of RFC 793 are met, and using the "C" notation "<<" for left-shift).
		SND.WND = SEG.WND << SND.Wind.Shift;
		SND.WL1 = SEG.SEQ;
		SND.WL2 = SEG.ACK;
		
		self.WND_last_updated = now;
		
		if SND.WND > MAX_SND_WND
		{
			self.MAX_SND_WND = SND.WND
		}
	}
	
	#[inline(always)]
	pub(crate) fn update_window<TCBA: TransmissionControlBlockAbstractions>(&mut self, SEG: &ParsedTcpSegment<TCBA>, now: MonotonicMillisecondTimestamp)
	{
		let SND = self;
		
		if SND.WL1 < SEG.SEQ || (SND.WL1 == SEG.SEQ && SND.WL2 <= SEG.ACK)
		{
			self.set_window(SEG, now)
		}
	}
	
	#[inline(always)]
	pub(crate) fn window_is_not_zero(&self) -> bool
	{
		!self.window_is_zero()
	}
	
	#[inline(always)]
	pub(crate) fn window_is_zero(&self) -> bool
	{
		let SND = self;
		SND.WND.is_zero()
	}
	
	#[inline(always)]
	pub(crate) fn all_data_acknowledged(&self) -> bool
	{
		self.retransmission_queue.is_empty()
	}
	
	#[inline(always)]
	pub(crate) fn has_data_unacknowledged(&self) -> bool
	{
		!self.all_data_acknowledged()
	}
	
	#[inline(always)]
	pub(crate) fn retransmission_queue_is_not_full(&self) -> bool
	{
		self.retransmission_queue.is_not_full()
	}
	
	#[inline(always)]
	pub(crate) fn rwnd(&self) -> u32
	{
		self.WND.into()
	}
	
	#[inline(always)]
	pub(crate) fn time_that_has_elapsed_since_send_window_last_updated(&self, now: Tick) -> MillisecondDuration
	{
		let send_window_last_updated = self.WND_last_updated;
		let now = now.to_milliseconds();
		debug_assert!(send_window_last_updated <= now, "send_window_last_updated '{}' exceeds now '{}'", send_window_last_updated, now);
		
		now - send_window_last_updated
	}
	
	#[inline(always)]
	pub(crate) fn buffer_data_to_send<DataWriter: Fn(&mut [u8]) -> usize>(&mut self, data_writer: DataWriter)
	{
		let wrote = data_writer(self.magic_ring_buffer.write_buffer());
		self.write_commit(wrote.into());
		
		
		
		
		
		
		// TODO: now what?
		
		
		// TODO: We can immediately send this much data:-
		transmission_control_block.maximum_data(now)
		
		
		
		
		
		
		
		xxx
	}
	
	#[inline(always)]
	pub(crate) fn data_to_transmit(&self, maximum_data: usize) -> &[u8]
	{
		// TODO
		xxx
	}
	
	#[inline(always)]
	pub(crate) fn data_to_transmit_commit(&self, count: usize)
	{
		// TODO
		xxx
	}
	
	#[inline(always)]
	pub(crate) fn transmitted(&mut self, now: MonotonicMillisecondTimestamp, starts_at: WrappingSequenceNumber, data_length_excluding_length_of_synchronize_and_finish_controls: u32, flags: Flags)
	{
		// TODO: Is this used?
		self.retransmission_queue.enqueue(now, starts_at, data_length_excluding_length_of_synchronize_and_finish_controls, flags)
	}
	
	#[inline(always)]
	fn acknowledged(&mut self, SEG_ACK: WrappingSequenceNumber, explicit_congestion_echo: bool) -> (u32, Option<MonotonicMillisecondTimestamp>, bool, bool)
	{
		// TODO: Verify!
		use self::RetransmissionSegmentDecreaseSequenceNumberLengthOutcome::*;
		
		let SND = self;
		
		debug_assert!(SEG_ACK > SND.UNA, "SEG.ACK should not be the same as (or less than) SND.UNA");
		
		let sequence_numbers_length = SEG_ACK - SND.UNA;
		debug_assert_ne!(sequence_numbers_length, 0, "SEG.ACK should not be the same as SND.UNA");
		
		let (bytes_acknowledged, unretransmitted_segment_timestamp, a_window_of_data_was_processed, explicit_congestion_echo) = self.retransmission_queue.acknowledged(sequence_numbers_length, explicit_congestion_echo).expect("Retransmission queue does not contain as much data as SND.NXT indicates");
		
		self.magic_ring_buffer.read_commit(bytes_acknowledged.into());
		
		(bytes_acknowledged, unretransmitted_segment_timestamp, a_window_of_data_was_processed, explicit_congestion_echo)
	}
}
