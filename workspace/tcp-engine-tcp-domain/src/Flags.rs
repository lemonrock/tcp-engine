// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


bitflags!
{
	/// Flags.
	pub struct Flags: u8
	{
		/// Congestion Window Reduced (CWR).
		///
		/// This is set by the sending host to indicate that it received a TCP segment with the ECN-Echo (`ECE`) flag set.
		///
		/// See RFC 3168 as modified by RFC 8311.
		const CongestionWindowReduced = 0b1000_0000;
		
		/// Explicit Congestion (ECN) Echo, 'ECE', also known as ECN-Echo.
		///
		/// * If the `SYN` flag is set, then the remote peer is Explicit Congestion (ECN) capable.
		/// * If the `SYN` flag is not set set, then the Internet Protocol (IP) version 4 or version 6 header before the TCP frame should have the Explicit Congestion (ECN) bits set to 0b11.
		///
		/// See RFC 3168 as modified by RFC 8311.
		const ExplicitCongestionEcho = 0b0100_0000;
		
		/// Urgent pointer (URG) field is valid.
		///
		/// RFC 793, Glossary, Page 84: "A control bit (urgent), occupying no sequence space, used to indicate that the receiving user should be notified to do urgent processing as long as there is data to be consumed with sequence numbers less than the value indicated in the urgent pointer".
		///
		/// RFC 6093 deprecates its use and permits it to be scrubbed (setting the urgent pointer to zero).
		const Urgent = 0b0010_0000;
		
		/// Acknowledgment (ACK).
		///
		/// RFC 793, Glossary, Page 79: "A control bit (acknowledge) occupying no sequence space, which indicates that the acknowledgment field of this segment specifies the next sequence number the sender of this segment is expecting to receive, hence acknowledging receipt of all previous sequence numbers".
		const Acknowledgment = 0b0001_0000;
		
		/// Push (PSH).
		///
		/// RFC 793, Glossary, Page 81: "A control bit occupying no sequence space, indicating that this segment contains data that must be pushed through to the receiving user".
		///
		/// RFC 1122 Dropped most of the requirements on this flag. In general, it indicates that the sender has no more data to send at the moment, ie it is a hint.
		///
		/// Near useless.
		const Push = 0b0000_1000;
		
		/// Reset connection (RST).
		///
		/// RFC 793, Glossary, Page 82: "A control bit (reset), occupying no sequence space, indicating that the receiver should delete the connection without further interaction.
		/// The receiver can determine, based on the sequence number and acknowledgment fields of the incoming segment, whether it should honor the reset command or ignore it.
		/// In no case does receipt of a segment containing RST give rise to a RST in response".
		const Reset = 0b0000_0100;
		
		/// Synchronize sequence numbers (SYN).
		///
		/// RFC 793, Glossary, Page 84: "A control bit in the incoming segment, occupying one sequence number, used at the initiation of a connection, to indicate where the sequence numbering will start".
		///
		/// Only the first packet sent from each end should have this flag set.
		const Synchronize = 0b0000_0010;
		
		/// Finish (FIN).
		///
		/// RFC 793, Glossary, Page 79: "A control bit (finis) occupying one sequence number, which indicates that the sender will send no more data or control occupying sequence space".
		///
		/// This is the last packet from the sender.
		const Finish = 0b0000_0001;
		
		/// Synchronize and Acknowledgment (SYNACK).
		const SynchronizeAcknowledgment = Self::Synchronize.bits | Self::Acknowledgment.bits;
		
		/// Acknowledgment with Push (PSHACK).
		///
		/// Often used as a 'probe'.
		const AcknowledgmentPush = Self::Acknowledgment.bits | Self::Push.bits;
		
		/// Finish and Acknowledgment (FINACK).
		const FinishAcknowledgment = Self::Finish.bits | Self::Acknowledgment.bits;
		
		/// Reset and Acknowledgment (RSTACK).
		const ResetAcknowledgment = Self::Reset.bits | Self::Acknowledgment.bits;
		
		/// Finish and Acknowledgment with Push (FINPSHACK).
		const FinishAcknowledgmentPush = Self::Finish.bits | Self::Acknowledgment.bits | Self::Push.bits;
		
		/// Synchronize with explict congestion notification support signalled.
		const SynchronizeExplicitCongestionEchoCongestionWindowReduced = Self::Synchronize.bits | Self::ExplicitCongestionEcho.bits | Self::CongestionWindowReduced.bits;
		
		/// Synchronize and Acknowledgment (SYNACK) explict congestion notification support signalled.
		const SynchronizeAcknowledgmentExplicitCongestionEcho = Self::Synchronize.bits | Self::ExplicitCongestionEcho.bits;
		
		/// Synchronize and Finish (SYNFIN)
		///
		/// A now invalid combination originally specified in RFC 1644 (T/TCP).
		const SynchronizeFinish = Self::Synchronize.bits | Self::Finish.bits;
	}
}

impl Flags
{
	/// Does not contain flags?
	#[inline(always)]
	pub fn does_not_contain(&self, flags: Self) -> bool
	{
		!self.contains(flags)
	}
	
	/// Contains Reset flag?
	#[inline(always)]
	pub fn contains_reset(&self) -> bool
	{
		self.contains(Flags::Reset)
	}
	
	/// Are all flags null?
	#[inline(always)]
	pub fn are_null(&self) -> bool
	{
		self.is_empty()
	}
	
	/// Has the Urgent flag?
	#[inline(always)]
	pub fn has_urgent_flag(&self) -> bool
	{
		self.contains(Flags::Urgent)
	}
}
