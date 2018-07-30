// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Managed explicit congenstion notification state.
#[derive(Default, Debug)]
pub struct ExplicitCongestionNotificationState
{
	/// This value should be `true` after a data packet (not a retransmission) has been received with a ECN code point of `CE`.
	///
	/// RFC 3168 Section 6.1.3 Paragraph 1: "If there is any ACK withholding implemented, as in current "delayed-ACK" TCP implementations where the TCP receiver can send an ACK for two arriving data packets, then the ECN-Echo flag in the ACK packet will be set to '1' if the CE codepoint is set in any of the data packets being acknowledged.
	/// That is, if any of the received data packets are CE packets, then the returning ACK has the ECN-Echo flag set".
	///
	/// RFC 3168 Section 6.1.3 Paragraph 2: "... the TCP receiver sets the ECN-Echo flag in a series of ACK packets sent subsequently.
	/// The TCP receiver uses the CWR flag received from the TCP sender to determine when to stop setting the ECN-Echo flag".
	///
	/// RFC 3168 Section 6.1.6 (Zero Window Probes): "When the TCP data receiver advertises a zero window, the TCP data sender sends window probes to determine if the receiver's window has increased.
	/// Window probe packets do not contain any user data except for the sequence number, which is a byte.
	/// If a window probe packet is dropped in the network, this loss is not detected by the receiver.
	/// Therefore, the TCP data sender MUST NOT set either an ECT codepoint or the CWR bit on window probe packets.
	///
	/// However, because window probes use exact sequence numbers, they cannot be easily spoofed in denial-of-service attacks.
	/// Therefore, if a window probe arrives with the CE codepoint set, then the receiver SHOULD respond to the ECN indications".
	acknowledgments_should_explicit_congestion_echo: bool,
	
	/// RFC 3168 Section 6.1.2 Paragraph 4: "When an ECN-Capable TCP sender reduces its congestion window for any reason (because of a retransmit timeout, a Fast Retransmit, or in response to an ECN Notification), the TCP sender sets the CWR flag in the TCP header of the first new data packet sent after the window reduction".
	///
	/// RFC 3168 Section 6.1.2 Paragraph 5: "If the new data packet carrying the CWR flag is dropped, then the TCP sender will have to again reduce its congestion window, and send another new data packet with the CWR flag set.
	/// Thus, the CWR bit in the TCP header SHOULD NOT be set on retransmitted packets".
	///
	/// RFC 3168 Section 6.1.2 Paragraph 6: "When the TCP data sender is ready to set the CWR bit after reducing the congestion window, it SHOULD set the CWR bit only on the first new data packet that it transmits".
	///
	/// RFC 3168 Section 6.1.3 Paragraph 3: "After the receipt of the CWR packet, acknowledgments for subsequent non-CE data packets do not have the ECN-Echo flag set".
	///
	/// In other words, we only set `CongestionWindowReduced` on an outgoing packet which has new data (and is not a zero window probe, which is, by definition, an old data packet filled with garbage).
	congestion_window_was_reduced_so_set_congestion_window_reduced_on_first_new_data_packet: bool,
}

impl ExplicitCongestionNotificationState
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn incoming_data_packet_had_congestion_window_reduced_flag_set(&mut self)
	{
		self.acknowledgments_should_explicit_congestion_echo = false
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn congestion_was_encountered(&mut self)
	{
		self.acknowledgments_should_explicit_congestion_echo = true
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn acknowledgments_should_explicit_congestion_echo(&self) -> bool
	{
		self.acknowledgments_should_explicit_congestion_echo
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn incoming_data_packet_had_explicit_congestion_echo_flag_set(&mut self)
	{
		self.congestion_window_was_reduced_so_set_congestion_window_reduced_on_first_new_data_packet = true
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn reduced_congestion_window(&mut self)
	{
		self.congestion_window_was_reduced_so_set_congestion_window_reduced_on_first_new_data_packet = true
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn set_congestion_window_reduced_on_first_new_data_packet_and_turn_off_signalling(&mut self) -> bool
	{
		let result = self.congestion_window_was_reduced_so_set_congestion_window_reduced_on_first_new_data_packet;
		self.congestion_window_was_reduced_so_set_congestion_window_reduced_on_first_new_data_packet = false;
		result
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn new(explicit_congestion_notification_supported: bool) -> Option<Self>
	{
		if explicit_congestion_notification_supported
		{
			Some(Default::default())
		}
		else
		{
			None
		}
	}
}
