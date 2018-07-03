// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct ParsedTcpSegment<'a, 'b, TCBA: 'a + TransmissionControlBlockAbstractions>
{
	now: MonotonicMillisecondTimestamp,
	packet: Option<TCBA::Packet>,
	interface: &'a Interface<TCBA>,
	source_internet_protocol_address: &'b TCBA::Address,
	SEG: &'b TcpSegment,
	tcp_options: TcpOptions,
	options_length: usize,
	payload_length: usize,
	SEQ: WrappingSequenceNumber,
	ACK: WrappingSequenceNumber,
	WND: SegmentWindowSize,
	LEN: u32,
}

impl<'a, 'b, TCBA: TransmissionControlBlockAbstractions> Drop for ParsedTcpSegment<'a, 'b, TCBA>
{
	#[inline(always)]
	fn drop(&mut self)
	{
		if let Some(packet) = self.packet
		{
			packet.free_packet()
		}
	}
}

/// Entry Point methods.
impl<'a, 'b, TCBA: TransmissionControlBlockAbstractions> ParsedTcpSegment<'a, 'b, TCBA>
{
	#[inline(always)]
	pub(crate) fn new(now: MonotonicMillisecondTimestamp, packet: TCBA::Packet, interface: &'a Interface<TCBA>, source_internet_protocol_address: &'b TCBA::Address, SEG: &'b TcpSegment, tcp_options: TcpOptions, options_length: usize, tcp_segment_length: usize) -> Self
	{
		let payload_length = tcp_segment_length - size_of::<TcpFixedHeader>() - options_length;
		
		Self
		{
			now,
			packet: Some(packet),
			interface,
			source_internet_protocol_address,
			SEG,
			tcp_options,
			options_length,
			payload_length,
			SEQ: SEG.SEQ(),
			ACK: SEG.ACK(),
			WND: SEG.WND(),
			LEN: SEG.LEN(payload_length),
		}
	}
	
	#[inline(always)]
	fn has_data(&self) -> bool
	{
		self.payload_length != 0
	}
	
	#[inline(always)]
	fn does_not_have_data(&self) -> bool
	{
		self.payload_length == 0
	}
	
	#[inline(always)]
	pub(crate) fn received_synchronize_when_state_is_listen_or_synchronize_received(&mut self, explicit_congestion_notification_supported: bool, md5_authentication_key: Option<&Rc<Md5PreSharedSecretKey>>)
	{
		if self.has_data()
		{
			invalid!(self, "TCP Synchronize packets are not supported with payloads as we use syncookies");
		}
		
		validate_authentication!(self);
		
		if unlikely(self.SEG.ACK() != WrappingSequenceNumber::Zero)
		{
			invalid!(self, "TCP Synchronize packets should have an initial ACK of zero (0)");
		}
		
		let maximum_segment_size = self.tcp_options.maximum_segment_size;
		let window_scale = self.tcp_options.window_scale;
		let selective_acknowledgment_permitted = self.tcp_options.selective_acknowledgment_permitted;
		let timestamps = self.tcp_options.timestamps;
		
		self.interface.send_synchronize_acknowledgment(self.now, self.reuse_packet(), self.source_internet_protocol_address, self, maximum_segment_size, window_scale, selective_acknowledgment_permitted, timestamps, explicit_congestion_notification_supported, md5_authentication_key);
	}
	
	#[inline(always)]
	pub(crate) fn received_acknowledgment_when_state_is_listen_or_synchronize_received(&mut self, md5_authentication_key: Option<&Rc<Md5PreSharedSecretKey>>)
	{
		validate_authentication!(self);
		
		let SEG = self;
		let interface = self.interface;
		
		let parsed_syncookie = match interface.validate_syncookie(self.source_internet_protocol_address, SEG)
		{
			Ok(parsed_syn_cookie) => parsed_syn_cookie,
			
			// RFC 793, Page 72: "If the segment acknowledgment is not acceptable, form a reset segment, <SEQ=SEG.ACK><CTL=RST>, and send it".
			//
			// We VIOLATE the RFC here; to send a Reset is to either reveal to a potential attacker that we exist OR to inadvertently abort an existing connection because of a spoofed packet.
			Err(()) => invalid!(SEG, "TCP Acknowledgment-like syncookie invalid (Reset <SEQ=SEG.ACK><CTL=RST> not sent)"),
		};
		
		let transmission_control_block = interface.new_transmission_control_block_for_incoming_segment(TransmissionControlBlock::new_for_sychronize_received_to_established(interface, self.source_internet_protocol_address, SEG, &self.tcp_options, parsed_syncookie, self.now, md5_authentication_key.map(|key_reference| key_reference.clone())));
		
		self.process_tcp_segment_when_state_is_other_than_listen_or_synchronize_received(transmission_control_block)
	}
	
	#[inline(always)]
	pub(crate) fn process_tcp_segment_when_state_is_other_than_listen_or_synchronize_received(&mut self, transmission_control_block: &mut TransmissionControlBlock<TCBA>)
	{
		use self::State::*;
		
		validate_authentication_when_synchronized!(self, transmission_control_block);
		
		match transmission_control_block.state()
		{
			Closed => unreachable_synthetic_state!("TCP state Closed is never actually used"),
			
			Listen => unreachable_synthetic_state!("TCP state Listen is replaced with SYN flood defences 'process_for_synchronize'"),
			
			SynchronizeSent => self.synchronize_sent(transmission_control_block),
			
			SynchronizeReceived => unreachable_synthetic_state!("TCP state SynchronizeReceived is replaced with SYN flood defences 'process_for_acknowledgment_of_syncookie'"),
			
			Established => self.established(transmission_control_block),
			
			CloseWait => self.close_wait(transmission_control_block),
			
			LastAcknowledgment => self.last_acknowledgment(transmission_control_block),
			
			FinishWait1 => self.finish_wait_1(transmission_control_block),
			
			FinishWait2 => self.finish_wait_2(transmission_control_block),
			
			Closing => self.closing(transmission_control_block),
			
			TimeWait => self.time_wait(transmission_control_block),
		}
	}
}

/// Handling for all states where these is a Transmission Control Block (TCB).
impl<'a, 'b, TCBA: TransmissionControlBlockAbstractions> ParsedTcpSegment<'a, 'b, TCBA>
{
	#[inline(always)]
	fn synchronize_sent(&mut self, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		let SEG = self;
		match SEG.syn_ack_fin_rst_ece_cwr_only_flags()
		{
			// RFC 5961 Section 3.2: "If the RST bit is set and the sequence number exactly matches the next expected sequence number (RCV.NXT), then TCP MUST reset the connection".
			Flags::ResetAcknowledgment =>
			{
				let SND = &transmission_control_block.SND;
				
				if SEG.ACK == SND.NXT
				{
					transmission_control_block.error_connection_reset(self.interface)
				}
				else
				{
					invalid!(SEG, "TCP ResetAcknowledgment in violation of RFC 5961, possible RST attack")
				}
			}
			
			// Processing Incoming Segments 3.1.1, 3.4.1
			Flags::SynchronizeAcknowledgment =>
			{
				transmission_control_block.disable_explicit_congestion_notification();
				
				self.synchronize_sent_received_acknowledgment(transmission_control_block)
			}
			
			// Processing Incoming Segments 3.1.1, 3.4.1
			// and
			// RFC 3168 Section 6.1.1: "We call a SYN-ACK packet with only the ECE flag set but the CWR flag not set an "ECN-setup SYN-ACK packet".
			Flags::SynchronizeAcknowledgmentExplicitCongestionEcho =>
			{
				// RFC 3168 Section 6.1.1: "If a host has received an ECN-setup SYN packet, then it MAY send an ECN-setup SYN-ACK packet.
				// Otherwise, it MUST NOT send an ECN-setup SYN-ACK packet".
				if transmission_control_block.explicit_congestion_notification_unsupported()
				{
					invalid!(SEG, "TCP SynchronizeAcknowledgment indicates support of ECN but we did not request it")
				}
				
				// RFC 3168 Section 6.1.1: "A host MUST NOT set ECT on SYN or SYN-ACK packets".
				if unlikely(self.packet.explicit_congestion_notification().is_ect_set())
				{
					invalid!(SEG, "TCP packet has an Internet Protocol Explicit Congestion Notification (ECN) ECT(0) or ECT(1) code point set for a SynchronizeAcknowledgment segment")
				}
				
				self.synchronize_sent_received_acknowledgment(transmission_control_block)
			}
			
			_ => invalid!(SEG, "TCP pure Resets, pure Acknowledgments and other technically valid oddities are ignored as they're likely to be spoofs, scans or attacks rather than errors"),
		}
	}
	
	#[inline(always)]
	fn established(&mut self, transmission_control_block: &mut TransmissionControlBlock<TCBA>)
	{
		reject_synchronize_finish!(self);
		
		let SEG = self;
		let SND = &mut transmission_control_block.SND;
		let MAX = &mut transmission_control_block.MAX;
		
		let TrueWindow = SEG.WND << SND.Wind.Shift;
		
		// In the following it is assumed that the segment is the idealized segment that begins at RCV.NXT and does not exceed the window.
		// Segments with higher begining sequence numbers SHOULD be held for later processing.
		// TODO: If the segment lies to the right of the end of the receive window, we need to hold on to it in an inbound (received out-of-order) queue.
		// Likewise, currently, we send an ACK for an unacceptable incoming segment; we could queue.
		// This area needs some finesse.
		
			// We can process this queue at the end of processing this tcp segment. We just need to know from where to start...
			// We may be able to part-process it, eg to send an ACK now.
		
		
		
		
		let timestamps_option = processing_incoming_segments_4_1_check_sequence_number!(self, transmission_control_block);
		
		processing_incoming_segments_4_2_check_the_rst_bit_established_fin_wait_1_fin_wait_2_close_wait!(self, transmission_control_block);
		
		self.processing_incoming_segments_4_3_check_security_and_precedence();
		
		processing_incoming_segments_4_4_check_the_syn_bit!(self, transmission_control_block);
		
		processing_incoming_segments_4_5_1_must_have_acknowledgment_flag_set!(self);
		
		rfc_5961_5_2_acknowledgment_is_acceptable!(self, transmission_control_block);
		
		self.processing_incoming_segments_4_5_2_2_established_and_similar_for_other_states(transmission_control_block);
		
		self.processing_incoming_segments_4_6_check_the_urg_bit();
		
		self.processing_incoming_segments_4_7_1_process_the_segment_text(transmission_control_block, true);
		
		self.processing_incoming_segments_4_8_2_1_transition_to_close_wait_if_finish_flag_set();
	}
	
	#[inline(always)]
	fn close_wait(&mut self, transmission_control_block: &mut TransmissionControlBlock<TCBA>)
	{
		reject_synchronize_finish!(self);
		
		let SEG = self;
		let SND = &mut transmission_control_block.SND;
		
		let TrueWindow = SEG.WND << SND.Wind.Shift;
		
		let timestamps_option = processing_incoming_segments_4_1_check_sequence_number!(self, transmission_control_block);
		
		processing_incoming_segments_4_2_check_the_rst_bit_established_fin_wait_1_fin_wait_2_close_wait!(self, transmission_control_block);
		
		self.processing_incoming_segments_4_3_check_security_and_precedence();
		
		processing_incoming_segments_4_4_check_the_syn_bit!(self, transmission_control_block);
		
		processing_incoming_segments_4_5_1_must_have_acknowledgment_flag_set!(self);
		
		rfc_5961_5_2_acknowledgment_is_acceptable!(self, transmission_control_block);
		
		self.processing_incoming_segments_4_5_2_2_established_and_similar_for_other_states(transmission_control_block);
		
		self.processing_incoming_segments_4_6_check_the_urg_bit();
		
		processing_incoming_segments_4_7_2_ignore_the_segment_text!(self);
		
		self.processing_incoming_segments_4_8_2_do_nothing_if_finish_flag_set();
	}
	
	#[inline(always)]
	fn last_acknowledgment(&mut self, transmission_control_block: &mut TransmissionControlBlock<TCBA>)
	{
		reject_synchronize_finish!(self);
		
		let SEG = self;
		let SND = &mut transmission_control_block.SND;
		
		let TrueWindow = SEG.WND << SND.Wind.Shift;
		
		let timestamps_option = processing_incoming_segments_4_1_check_sequence_number!(self, transmission_control_block);
		
		processing_incoming_segments_4_2_check_the_rst_bit_closing_last_acknowledgment_time_wait!(self, transmission_control_block);
		
		self.processing_incoming_segments_4_3_check_security_and_precedence();
		
		processing_incoming_segments_4_4_check_the_syn_bit!(self, transmission_control_block);
		
		processing_incoming_segments_4_5_1_must_have_acknowledgment_flag_set!(self);
		
		rfc_5961_5_2_acknowledgment_is_acceptable!(self, transmission_control_block);
		
		// ACK ON
		// TODO: The only thing that can arrive in this state is an acknowledgment of our FIN. If our FIN is now acknowledged, delete the TCB, enter the CLOSED state, and return.
		
		self.processing_incoming_segments_4_6_check_the_urg_bit();
		
		processing_incoming_segments_4_7_2_ignore_the_segment_text!(self);
		
		self.processing_incoming_segments_4_8_2_do_nothing_if_finish_flag_set();
	}
	
	#[inline(always)]
	fn finish_wait_1(&mut self, transmission_control_block: &mut TransmissionControlBlock<TCBA>)
	{
		reject_synchronize_finish!(self);
		
		let SEG = self;
		let SND = &mut transmission_control_block.SND;
		
		let TrueWindow = SEG.WND << SND.Wind.Shift;
		
		let timestamps_option = processing_incoming_segments_4_1_check_sequence_number!(self, transmission_control_block);
		
		processing_incoming_segments_4_2_check_the_rst_bit_established_fin_wait_1_fin_wait_2_close_wait!(self, transmission_control_block);
		
		self.processing_incoming_segments_4_3_check_security_and_precedence();
		
		processing_incoming_segments_4_4_check_the_syn_bit!(self, transmission_control_block);
		
		processing_incoming_segments_4_5_1_must_have_acknowledgment_flag_set!(self);
		
		rfc_5961_5_2_acknowledgment_is_acceptable!(self, transmission_control_block);
		
		self.processing_incoming_segments_4_5_2_2_established_and_similar_for_other_states(transmission_control_block);
		// TODO: In addition to the processing for the ESTABLISHED state, if our FIN is now acknowledged then enter FIN-WAIT-2 and continue processing in that state.
		
		self.processing_incoming_segments_4_6_check_the_urg_bit();
		
		self.processing_incoming_segments_4_7_1_process_the_segment_text(transmission_control_block, true);
		
		self.processing_incoming_segments_4_8_2_2_transition_to_time_wait_or_closing_if_finish_flag_set();
	}
	
	#[inline(always)]
	fn finish_wait_2(&mut self, transmission_control_block: &mut TransmissionControlBlock<TCBA>)
	{
		reject_synchronize_finish!(self);
		
		let SEG = self;
		let SND = &mut transmission_control_block.SND;
		
		let TrueWindow = SEG.WND << SND.Wind.Shift;
		
		let timestamps_option = processing_incoming_segments_4_1_check_sequence_number!(self, transmission_control_block);
		
		processing_incoming_segments_4_2_check_the_rst_bit_established_fin_wait_1_fin_wait_2_close_wait!(self, transmission_control_block);
		
		self.processing_incoming_segments_4_3_check_security_and_precedence();
		
		processing_incoming_segments_4_4_check_the_syn_bit!(self, transmission_control_block);
		
		processing_incoming_segments_4_5_1_must_have_acknowledgment_flag_set!(self);
		
		rfc_5961_5_2_acknowledgment_is_acceptable!(self, transmission_control_block);
		
		self.processing_incoming_segments_4_5_2_2_established_and_similar_for_other_states(transmission_control_block);
		// TODO: In addition to the processing for the ESTABLISHED state, if the retransmission queue is empty, the user’s CLOSE can be acknowledged (“ok”) but do not delete the TCB.
		
		self.processing_incoming_segments_4_6_check_the_urg_bit();
		
		self.processing_incoming_segments_4_7_1_process_the_segment_text(transmission_control_block, true);
		
		self.processing_incoming_segments_4_8_2_3_transition_to_time_wait_if_finish_flag_set();
	}
	
	#[inline(always)]
	fn closing(&mut self, transmission_control_block: &mut TransmissionControlBlock<TCBA>)
	{
		reject_synchronize_finish!(self);
		
		let SEG = self;
		let SND = &mut transmission_control_block.SND;
		
		let TrueWindow = SEG.WND << SND.Wind.Shift;
		
		let timestamps_option = processing_incoming_segments_4_1_check_sequence_number!(self, transmission_control_block);
		
		processing_incoming_segments_4_2_check_the_rst_bit_closing_last_acknowledgment_time_wait!(self, transmission_control_block);
		
		self.processing_incoming_segments_4_3_check_security_and_precedence();
		
		processing_incoming_segments_4_4_check_the_syn_bit!(self, transmission_control_block);
		
		processing_incoming_segments_4_5_1_must_have_acknowledgment_flag_set!(self);
		
		rfc_5961_5_2_acknowledgment_is_acceptable!(self, transmission_control_block);
		
		self.processing_incoming_segments_4_5_2_2_established_and_similar_for_other_states(transmission_control_block);
		// TODO: In addition to the processing for the ESTABLISHED state, if the ACK acknowledges our FIN then enter the TIME-WAIT state, otherwise ignore the segment.
		
		self.processing_incoming_segments_4_6_check_the_urg_bit();
		
		processing_incoming_segments_4_7_2_ignore_the_segment_text!(self);
		
		self.processing_incoming_segments_4_8_2_do_nothing_if_finish_flag_set();
	}
	
	// TODO: https://tools.ietf.org/html/rfc6191 - Reducing the TIME-WAIT State Using TCP Timestamps
	// TODO: RFC 1122 Section 4.2.2.13 Paragraph 4: "When a connection is closed actively, it MUST linger in TIME-WAIT state for a time 2xMSL (Maximum Segment Lifetime).
	// However, it MAY accept a new SYN from the remote TCP to reopen the connection directly from TIME-WAIT state, if it:-
	// (1) assigns its initial sequence number for the newconnection to be larger than the largest sequencenumber it used on the previous connection incarnation, and
	// (2) returns to TIME-WAIT state if the SYN turns out to be an old duplicate".
	// TODO
	#[inline(always)]
	fn time_wait(&mut self, transmission_control_block: &mut TransmissionControlBlock<TCBA>)
	{
		reject_synchronize_finish!(self);
		
		let SEG = self;
		let SND = &mut transmission_control_block.SND;
		
		let TrueWindow = SEG.WND << SND.Wind.Shift;
		
		let timestamps_option = processing_incoming_segments_4_1_check_sequence_number!(self, transmission_control_block);
		
		// TODO: RFC 1337 Section 4: "Of the three fixes described in the previous section, fix (F1), ignoring RST segments in TIME-WAIT state, seems like the best short-term solution.
		// NOTE: This is not without controversy and is disabled by default in Linux. Linux however does not conform to RFC 793 either - see https://serverfault.com/questions/787624/why-isnt-net-ipv4-tcp-rfc1337-enabled-by-default .
		
		processing_incoming_segments_4_2_check_the_rst_bit_closing_last_acknowledgment_time_wait!(self, transmission_control_block);
		
		self.processing_incoming_segments_4_3_check_security_and_precedence();
		
		processing_incoming_segments_4_4_check_the_syn_bit!(self, transmission_control_block);
		
		processing_incoming_segments_4_5_1_must_have_acknowledgment_flag_set!(self);
		
		rfc_5961_5_2_acknowledgment_is_acceptable!(self, transmission_control_block);
		
		// ACK ON
		// TODO: The only thing that can arrive in this state is a retransmission of the remote FIN. Acknowledge it, and restart the 2 MSL timeout.
		
		self.processing_incoming_segments_4_6_check_the_urg_bit();
		
		processing_incoming_segments_4_7_2_ignore_the_segment_text!(self);
		
		self.processing_incoming_segments_4_8_2_7_restart_time_wait_time_out_if_finish_flag_set();
	}
}

/// Supporting logic.
impl<'a, 'b, TCBA: TransmissionControlBlockAbstractions> ParsedTcpSegment<'a, 'b, TCBA>
{
	fn synchronize_sent_received_acknowledgment(&mut self, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		// TODO: retransmision_time_out.reset_after_establishment_of_state_if_we_sent_the_first_synchronize_segment_and_the_timer_expired();
		
		let SEG = self;
		
		// RFC 3168 Section 6.1.1: "A host MUST NOT set ECT on SYN or SYN-ACK packets".
		if unlikely(self.packet.explicit_congestion_notification().is_ect_set())
		{
			invalid!(SEG, "TCP packet has an Internet Protocol Explicit Congestion Notification (ECN) ECT(0) or ECT(1) code point set for a SynchronizeAcknowledgment segment")
		}
		
		rfc_5961_5_2_acknowledgment_is_acceptable!(self, transmission_control_block);
		
		if self.acknowledgment_is_acceptable_after_applying_rfc_5961_section_5_2_paragraph_1(transmission_control_block)
		{
			let RCV = &mut transmission_control_block.RCV;
			let SND = &mut transmission_control_block.SND;
			
			RCV.NXT = SEG.SEQ + 1;
			let IRS = SEG.SEQ;
			
			transmission_control_block.maximum_segment_size_to_send_to_remote = MaximumSegmentSizeOption::maximum_segment_size_to_send_to_remote(self.tcp_options.maximum_segment_size, self.interface, self.source_internet_protocol_address);
			
			// Processing Incoming Segments 3.4.1.1.
			match self.tcp_options.window_scale
			{
				Some(window_scale_option) =>
				{
					SND.Wind.Shift = window_scale_option;
				}
				
				None =>
				{
					SND.Wind.Shift = WindowScaleOption::Zero;
					RCV.Wind.Shift = WindowScaleOption::Zero;
				}
			}
			
			// Processing Incoming Segments 3.4.1.1.
			match self.tcp_options.timestamps
			{
				Some(timestamps_option) =>
				{
					transmission_control_block.timestamping.as_ref().unwrap().borrow_mut().TS_Recent = timestamps_option.TSval;
				}
				
				None => transmission_control_block.timestamping = None,
			}
			
			if self.tcp_options.selective_acknowledgments_permitted
			{
				transmission_control_block.selective_acknowledgments_permitted = true;
			}
			
			let MAX = &mut transmission_control_block.MAX;
			
			SND.WND = SEG.WND << SND.Wind.Shift;
			SND.WL1 = SEG.SEQ;
			SND.WL2 = SEG.ACK;
			if SND.WND > MAX.SND.WND
			{
				MAX.SND.WND = SND.WND
			}
			
			self.process_acceptable_acknowledgment(transmission_control_block, SND);
			transmission_control_block.set_state(State::Established);
			transmission_control_block.congestion_control.recalculate_sender_maximum_segment_size_when_entering_established_state();
			transmission_control_block.events_receiver.client_connection_established();
			
			// TODO: If using TCP Fast-Open, we can send data on the third part of the three-way handshake
			// TODO: ?Thus we need to call processing_incoming_segments_4_7_process_the_segment_text() before sending this ack?
			self.interface.send_final_acknowledgment_of_three_way_handshake(self.reuse_packet(), transmission_control_block, self.now, Flags::Acknowledgment, SND.NXT, RCV.NXT);
			
			self.processing_incoming_segments_4_6_check_the_urg_bit();
			
			self.processing_incoming_segments_4_7_1_process_the_segment_text(transmission_control_block, false);
		}
		else
		{
			invalid!(SEG, "TCP simultaneous open or invalid ACK ignored; Acknowledge or Reset not sent");
		}
	}
	
	/// Processing Incoming Segments 4.1.3: "R2: RFC 793 Page 69".
	///
	/// RFC 793 page 25: "A segment is judged to occupy a portion of valid receive sequence space ... Due to zero windows and zero length segments, we have four cases for the acceptability of an incoming segment".
	#[inline(always)]
	fn processing_incoming_segments_4_1_3_r2_segment_is_acceptable_because_it_occupies_a_portion_of_valid_receive_sequence_space(&self, transmission_control_block: &TransmissionControlBlock<TCBA>) -> bool
	{
		let SEG = self;
		let RCV = &transmission_control_block.RCV;
		
		// Processing Incoming Segments 4.1.3 Table 4.1: Tests for Acceptability of an Incoming Segment.
		if SEG.LEN == 0
		{
			let first_inclusive_sequence_number = SEG.SEQ;
			
			if RCV.WND == WindowSize::Zero
			{
				first_inclusive_sequence_number == RCV.NXT
			}
			else
			{
				let RCV_END = RCV.NXT + RCV.WND;
				RCV.NXT <= first_inclusive_sequence_number && first_inclusive_sequence_number < RCV_END
			}
		}
		else
		{
			if RCV.WND == WindowSize::Zero
			{
				false
			}
			else
			{
				let first_inclusive_sequence_number = SEG.SEQ;
				let RCV_END = RCV.NXT + RCV.WND;
				(RCV.NXT <= first_inclusive_sequence_number && first_inclusive_sequence_number < RCV_END) ||
				{
					let last_inclusive_sequence_number = SEG.SEQ + (SEG.LEN - 1);
					(RCV.NXT <= last_inclusive_sequence_number && last_inclusive_sequence_number < RCV_END)
				}
				
			}
		}
	}

	/// Processing Incoming Segments 4.1.3: RFC 7323 Section 5.3, Point R3.
	#[inline(always)]
	fn processing_incoming_segments_4_1_3_r3(&self, SEG_TSval: NetworkEndianU32)
	{
		let SEG = self;
		timestamping.update_TS_Recent_if_appropriate(SEG_TSval, SEG.SEQ)
	}
	
	/// Processing Incoming Segments 4.3: Check Security & Precedence.
	#[inline(always)]
	fn processing_incoming_segments_4_3_check_security_and_precedence(&self)
	{
		// No implementation as per RFC 2873.
	}
	
	/// Processing of the acknowledgment for Processing Incoming Segments 4.5.2.2, 4.5.2.5 and the first parts of 4.5.2.4 and 4.5.2.6.
	#[inline(always)]
	fn processing_incoming_segments_4_5_2_2_established_and_similar_for_other_states(&mut self, transmission_control_block: &mut TransmissionControlBlock<TCBA>)
	{
		let SEG = self;
		let SND = &mut transmission_control_block.SND;
		
		if self.acknowledgment_is_acceptable_after_applying_rfc_5961_section_5_2_paragraph_1(transmission_control_block)
		{
			if let Some(explicit_congestion_notification_state) = transmission_control_block.explicit_congestion_notification_state()
			{
				if self.all_flags().contains(Flags::ExplicitCongestionEcho)
				{
					explicit_congestion_notification_state.incoming_data_packet_had_explicit_congestion_echo_flag_set();
					
					// TODO: RFC 3168 6.1.2 Paragraph 3: "... the sending TCP MUST reset the retransmit timer on receiving the ECN-Echo packet when the congestion window is one (1 MSS)".
					
					// We need to reduce CWR; the line above ensures the CWR flag gets set.
					CongestionControlSignal::CC_ECN.signal();
					
					/*
					
					TCP should not react to congestion indications more than once every window of data (or more loosely, more than once every round-trip time). That is, the TCP sender's congestion window should be reduced only once in response to a series of dropped and/or CE packets from a single window of data.
   
   					Similar logic is given for RTT calculations.
   					
   					What is a 'window of data'? One segment that we sent initially? - probably.
   					
   					
   					
   					When an ECN-Capable TCP sender reduces its congestion window for any reason (because of a retransmit timeout, a Fast Retransmit, or in response to an ECN Notification), the TCP sender sets the CWR flag in the TCP header of the first new data packet sent after the window reduction.
					*/
				}
			}
			
			let bytes_acknowledged = SND.UNA - SEG.ACK;
			
			let most_recent_segment_timestamp =
			{
				SND.UNA = SEG.ACK;
				transmission_control_block.remove_all_sent_segments_up_to(SND.UNA)
			};
			
			transmission_control_block.record_last_acknowledgment_which_moved_SND_UNA(self.now);
			transmission_control_block.increase_bytes_acknowledged(bytes_acknowledged);
			
			
			
			// TODO: RFC 3465 Section 3.1: "When bytes_acked becomes greater than or equal to the value of the congestion window, bytes_acked is reduced by the value of cwnd".
			
			// Processing Incoming Segments 4.5.2.2: "Also compute a new estimate of round-trip time.
			// If Snd.TS.OK bit is on, use Snd.TSclock - SEG.TSecr; otherwise, use the elapsed time since the first segment in the retransmission queue was sent".
			if let Some(timestamp) = most_recent_segment_timestamp
			{
				match timestamps_option
				{
					Some(timestamps_option) => transmission_control_block.adjust_retransmission_time_out_based_on_timestamps(self.now, timestamps_option),
					
					None => transmission_control_block.adjust_retransmission_time_out_based_on_acknowledgments(self.now, most_recent_segment_timestamp),
				}
			}
			
			if SND.WL1 < SEG.SEQ || (SND.WL1 == SEG.SEQ && SND.WL2 <= SEG.ACK)
			{
				SND.WND = SEG.WND << SND.Wind.Shift;
				SND.WL1 = SEG.SEQ;
				SND.WL2 = SEG.ACK;
				if SND.WND > MAX.SND.WND
				{
					MAX.SND.WND = SND.WND
				}
			}
		}
		else
		{
			// TODO: Verify that this rule should be applied.
			// Errata 4785: "If the ACK is a duplicate\* (SEG.ACK <= SND.UNA), it can be ignored except when equality is met (SEG.ACK = SND.UNA)".
			//
			// \* Note that this definition of duplicate is not used below.
			if SND.UNA == SEG.ACK
			{
				if SND.WL1 < SEG.SEQ || (SND.WL1 == SEG.SEQ && SND.WL2 <= SEG.ACK)
				{
					SND.WND = SEG.WND << SND.Wind.Shift;
					SND.WL1 = SEG.SEQ;
					SND.WL2 = SEG.ACK;
					if SND.WND > MAX.SND.WND
					{
						MAX.SND.WND = SND.WND
					}
				}
			}
			
			// TODO: Do not process out-of-order segments as such [although there are some congestion control rules]
			
			// RFC 5681 Section 2: Duplicate Acknowledgment:
			// "An acknowledgment is considered a "duplicate" in the following algorithms when:-
			//
			// * (a) the receiver of the ACK has outstanding data,
			// * (b) the incoming acknowledgment carries no data,
			// * (c) the SYN and FIN bits are both off\*,
			// * (d) the acknowledgment number is equal to the greatest acknowledgment received on the given connection (TCP.UNA from [RFC793]) and
			// * (e) the advertised window in the incoming acknowledgment equals the advertised window in the last incoming acknowledgment".
			//
			// \* The `SYN` bit is already checked for in Processing Incoming Segments 4.4.
			let segment_acknowledgment_number_is_equal_to_the_greatest = SND.UNA == SEG.ACK;
			let is_a_duplicate_acknowledgment = transmission_control_block.has_outstanding_data() && self.does_not_have_data() && self.finish_flag_unset() && segment_acknowledgment_number_is_equal_to_the_greatest && (SEG.WND << SND.Wind.Shift) == SND.WND;
			if is_a_duplicate_acknowledgment
			{
				transmission_control_block.increment_duplicate_acknowledgments_received_without_any_intervening_acknwoledgments_which_moved_SND_UNA();
			}
			
			// TODO: Following 2 kinds of acks should not affect dupack counting: 1) Old acks [test above should cover this] 2) Acks with SACK but without any new SACK information in them. These could result from any anomaly in the network like a switch duplicating packets or a possible DoS attack.
			
		}
		
		// actually, has now become zero...
		if SND.WND.has_now_reached_zero()
		{
			// TODO consider scheduling a retransmission time-out zero-window probe alarm.
			
			//   The sending TCP must be prepared to accept from the user and send at
			//  least one octet of new data even if the send window is zero.  The
			//  sending TCP must regularly retransmit to the receiving TCP even when
			//  the window is zero.
			// Two minutes is recommended for the retransmission
			//  interval when the window is zero.
			
			
			
			/*
				Window probe packets do not contain any user data except for the sequence number, which is a byte (segment size is one).
				The sequence number is equal to the next expected sequence number.
			*/
		}
		
	}
	
	/// Processing Incoming Segments 4.6: Check the URG bit.
	fn processing_incoming_segments_4_6_check_the_urg_bit(&self)
	{
		// No implementation as we do not support Urgent.
	}
	
	#[inline(always)]
	fn processing_incoming_segments_4_8_2_do_nothing_if_finish_flag_set(&self)
	{
		// No implementation as nothing to do regardless of whether finish flag is set or not.
	}
	
	/// Processing Incoming Segments 4.7.1.
	#[inline(always)]
	fn processing_incoming_segments_4_7_1_process_the_segment_text(&mut self, transmission_control_block: &mut TransmissionControlBlock<TCBA>, this_is_after_syn_ack: bool)
	{
		if self.does_not_have_data()
		{
			return
		}
		
		// TODO: CWR flag should only be set on data segments that have not been re-txmtd and not on zero window probes.
		// TODO: ECN flag should only be set on ACKs.
		
		if let Some(explicit_congestion_notification_state) = transmission_control_block.explicit_congestion_notification_state()
		{
			// RFC 3168 Section 6.1.1: "A host MUST NOT set ECT on SYN or SYN-ACK packets"; hence congestion_encountered() is false and the CWR flag should not be set.
			if likely(this_is_after_syn_ack)
			{
				if self.all_flags().contains(Flags::CongestionWindowReduced)
				{
					explicit_congestion_notification_state.incoming_data_packet_had_congestion_window_reduced_flag_set();
				}
				
				// RFC 3168 Section 6.5: "ECN-capable TCP implementations MUST NOT set either ECT codepoint (ECT(0) or ECT(1)) in the IP header for retransmitted data packets, and that the TCP data receiver SHOULD ignore the ECN field on arriving data packets that are outside of the receiver's current window".
				//
				// processing_incoming_segments_4_1_3_r2! checks for data packets that are outside of the current window, so it should not be possible for the SHOULD in the above statement to be violated.
				if self.packet.explicit_congestion_notification().congestion_encountered()
				{
					explicit_congestion_notification_state.congestion_was_encountered()
				}
			}
		}
		
		
		
		// NOTE: RCV.NXT <= SEG.SEQ, ie this segment might be out-of-order but WITHIN the window.
		
		/*
		
		RFC 1122 Section 4.2.2.21  Acknowledging Queued Segments: RFC-793 Section 3.9

            A TCP MAY send an ACK segment acknowledging RCV.NXT when a
            valid segment arrives that is in the window but not at the
            left window edge.




Internet Engineering Task Force                                [Page 94]


RFC1122                  TRANSPORT LAYER -- TCP             October 1989


            DISCUSSION:
                 RFC-793 (see page 74) was ambiguous about whether or
                 not an ACK segment should be sent when an out-of-order
                 segment was received, i.e., when SEG.SEQ was unequal to
                 RCV.NXT.

                 One reason for ACKing out-of-order segments might be to
                 support an experimental algorithm known as "fast
                 retransmit".   With this algorithm, the sender uses the
                 "redundant" ACK's to deduce that a segment has been
                 lost before the retransmission timer has expired.  It
                 counts the number of times an ACK has been received
                 with the same value of SEG.ACK and with the same right
                 window edge.  If more than a threshold number of such
                 ACK's is received, then the segment containing the
                 octets starting at SEG.ACK is assumed to have been lost
                 and is retransmitted, without awaiting a timeout.  The
                 threshold is chosen to compensate for the maximum
                 likely segment reordering in the Internet.  There is
                 not yet enough experience with the fast retransmit
                 algorithm to determine how useful it is.
                 
                 RJC: This is the algorithm used in FreeBSD.
		
		*/
		
		// TODO: SEE RFC 5961 Section 5: "Blind Data Injection Attack" mitigations.
		
		let SND = &transmission_control_block.SND;
		let RCV = &transmission_control_block.RCV;
		
		xxxx;
		
		// Once the TCP takes responsibility for the data it advances RCV.NXT over the data accepted, and adjusts RCV.WND as apporopriate to the current buffer availability.
		// The total of RCV.NXT and RCV.WND should not be reduced.
		
		// Send an acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>.
		// This acknowledgment should be piggybacked on a segment being transmitted if possible without incurring undue delay.
		self.interface.send_acknowledgment(self.reuse_packet(), transmission_control_block, self.now, Flags::Acknowledgment, SND.NXT, RCV.NXT)
		
		// Please note the window management suggestions in section 3.7.
	}
	
	#[inline(always)]
	fn processing_incoming_segments_4_8_2_1_transition_to_close_wait_if_finish_flag_set(&self)
	{
		if self.finish_flag_set()
		{
			// TODO: Whatever we should do for a close-wait transition.
		}
	}
	
	#[inline(always)]
	fn processing_incoming_segments_4_8_2_2_transition_to_time_wait_or_closing_if_finish_flag_set(&self)
	{
		if self.finish_flag_set()
		{
			// TODO: If our FIN has been ACKed (perhaps in this segment), then enter TIME-WAIT, start the time-wait timer, turn off the other timers
			// TODO: else enter CLOSING state.
		}
	}
	
	#[inline(always)]
	fn processing_incoming_segments_4_8_2_3_transition_to_time_wait_if_finish_flag_set(&self)
	{
		if self.finish_flag_set()
		{
			// TODO: ??? Enter the Time-wait state, start the time-wait timer, make sure all other timers are turned off.
			// We should have per-state timers, replacing the user_time_out timer, which auto-kill and forcibly close the connection on expiry. These may or may not send a reset.
		}
	}
	
	#[inline(always)]
	fn processing_incoming_segments_4_8_2_7_restart_time_wait_time_out_if_finish_flag_set(&self)
	{
		if self.finish_flag_set()
		{
			// TODO: Restart the 2 MSL time-wait timeout.
		}
	}
	
	#[inline(always)]
	fn ignore(&self)
	{
		invalid!(self, "TCP segment ignored")
	}
	
	#[inline(always)]
	fn acknowledgment_is_acceptable_after_applying_rfc_5961_section_5_2_paragraph_1(&self, transmission_control_block: &TransmissionControlBlock<TCBA>) -> bool
	{
		let SEG = self;
		// RFC 793 was `SND.UNA < SEG.ACK && SEG.ACK <= SND.NXT`.
		// Since RFC 5961 Section 5.2 paragraph 1 has already been applied, this test simplifies to `SND.UNA < SEG.ACK`.
		SND.UNA < SEG.ACK
	}
	
	#[inline(always)]
	fn payload_data_pointer(&self) -> NonNull<u8>
	{
		self.SEG.payload_data_pointer(self.options_length)
	}
	
	#[inline(always)]
	fn reuse_packet(&mut self) -> TCBA::Packet
	{
		self.packet.take().unwrap()
	}
	
	#[inline(always)]
	pub(crate) fn remote_port_local_port(&self) -> RemotePortLocalPort
	{
		self.source_port_destination_port().remote_port_local_port()
	}
	
	#[inline(always)]
	pub(crate) fn source_port_destination_port(&self) -> SourcePortDestinationPort
	{
		self.SEG.source_port_destination_port()
	}
}

/// Flags
impl<'a, 'b, TCBA: 'a + TransmissionControlBlockAbstractions> ParsedTcpSegment<'a, 'b, TCBA>
{
	#[inline(always)]
	fn acknowledgment_flag_set(&self) -> bool
	{
		self.all_flags().contains(Flags::Acknowledgment)
	}
	
	#[inline(always)]
	fn acknowledgment_flag_unset(&self) -> bool
	{
		self.all_flags().does_not_contain(Flags::Acknowledgment)
	}
	
	#[inline(always)]
	fn reset_flag_set(&self) -> bool
	{
		self.all_flags().contains(Flags::Reset)
	}
	
	#[inline(always)]
	fn reset_flag_unset(&self) -> bool
	{
		self.all_flags().does_not_contain(Flags::Reset)
	}
	
	#[inline(always)]
	fn synchronize_flag_set(&self) -> bool
	{
		self.all_flags().contains(Flags::Synchronize)
	}
	
	#[inline(always)]
	fn synchronize_flag_unset(&self) -> bool
	{
		self.all_flags().does_not_contain(Flags::Synchronize)
	}
	
	#[inline(always)]
	fn finish_flag_set(&self) -> bool
	{
		self.all_flags().contains(Flags::Finish)
	}
	
	#[inline(always)]
	fn finish_flag_unset(&self) -> bool
	{
		self.all_flags().does_not_contain(Flags::Finish)
	}
	
	#[inline(always)]
	fn all_flags(&self) -> Flags
	{
		self.SEG.all_flags()
	}
}
