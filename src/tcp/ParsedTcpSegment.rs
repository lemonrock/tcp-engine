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
		let payload_length = Self::payload_length(tcp_segment_length, options_length);
		
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
	fn all_flags(&self) -> Flags
	{
		self.SEG.all_flags()
	}
	
	// TODO: We handle incoming ECN requests, but we don't do anything with them yet (RFC 3168) (We will need to add support for them to the syncookie).
	#[inline(always)]
	pub(crate) fn received_synchronize_when_state_is_listen_or_synchronize_received(&mut self, _explicit_congestion_notification_supported: bool)
	{
		if self.has_data()
		{
			invalid!(self, "TCP Synchronize packets are not supported with payloads as we use syncookies");
		}
		
		let maximum_segment_size = self.tcp_options.maximum_segment_size;
		let window_scale = self.tcp_options.window_scale;
		let selective_acknowledgment_permitted = self.tcp_options.selective_acknowledgment_permitted;
		let timestamps = self.tcp_options.timestamps;
		
		self.interface.send_synchronize_acknowledgment(self.now, self.packet.take().unwrap(), self.source_internet_protocol_address, self, maximum_segment_size, window_scale, selective_acknowledgment_permitted, timestamps);
	}
	
	#[inline(always)]
	pub(crate) fn received_acknowledgment_when_state_is_listen_or_synchronize_received(&self, push_flag_set: bool)
	{
		let SEG = self;
		let interface = self.interface;
		
		// TODO: This code can be made more efficient by converting into a macro to avoid the need to evaluate a result.
		let parsed_syncookie = match interface.validate_syncookie(self.source_internet_protocol_address, SEG)
		{
			// RFC 793, Page 72: "If the segment acknowledgment is not acceptable, form a reset segment, <SEQ=SEG.ACK><CTL=RST>, and send it".
			//
			// We VIOLATE the RFC here; to send a Reset is to either reveal to a potential attacker that we exist OR to inadvertently abort an existing connection because of a spoofed packet.
			Err(()) => invalid!(SEG, "TCP Acknowledgment-like syncookie invalid (Reset <SEQ=SEG.ACK><CTL=RST> not sent)"),
			
			Ok(parsed_syn_cookie) => parsed_syn_cookie,
		};
		
		let transmission_control_block = TransmissionControlBlock::new_for_listen(interface, self.source_internet_protocol_address, SEG, &self.tcp_options, self.now);
		
		interface.new_transmission_control_block_for_incoming_segment(transmission_control_block);
		
		if push_flag_set || self.has_data()
		{
			self.data_in(push_flag_set)
		}
	}
	
	#[inline(always)]
	pub(crate) fn process_tcp_segment_when_state_is_other_than_listen_or_synchronize_received(&mut self, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		use self::State::*;
		
		macro_rules! check_sequence_number_segment_is_unacceptable
		{
			($self: ident, $transmission_control_block: ident, $reason: expr) =>
			{
				{
					if $self.reset_flag_unset()
					{
						$self.interface.send_acknowledgment(self.packet.take().unwrap(), $transmission_control_block, Flags::Acknowledgment, SND.NXT, RCV.NXT);
					}
					invalid!($self, $reason)
				}
			}
		}
		
		// Processing Incoming Segments 4.1.1: RFC 7323, Section 5.3, Point R1.
		macro_rules! check_sequence_number_r1
		{
			($self: ident, $transmission_control_block: ident, $timestamping: ident, $timestamps_option: ident) =>
			{
				{
					let SEG_TSval = $timestamps_option.TSval;
					
					if $timestamping.is_TS_Recent_greater_than(SEG_TSval) && $timestamping.is_TS_Recent_valid() && $self.reset_flag_unset()
					{
						check_sequence_number_segment_is_unacceptable!($self, $transmission_control_block, "TCP segment was not acceptable as it did not have a recent enough timestamp")
					}
					
					($timstamping, SEG_TSval)
				}
			}
		}
		
		// Processing Incoming Segments 4.1.2: RFC 793 Page 69 / RFC 7323, Section 5.3, Point R2.
		macro_rules! check_sequence_number_r2
		{
			($self: ident, $transmission_control_block: ident) =>
			{
				if !$self.segment_is_acceptable_because_it_occupies_a_portion_of_valid_receive_sequence_space($transmission_control_block)
				{
					check_sequence_number_segment_is_unacceptable!($self, $transmission_control_block, "TCP segment was not acceptable as it did not occupy a portion of the valid receive sequence space")
				}
			}
		}
		
		// Processing Incoming Segments 4.1.3: RFC 7323 Section 5.3, Point R3.
		macro_rules! check_sequence_number_r3
		{
			($self: ident, $SEG_TSval: ident) =>
			{
				{
					let SEG = $self;
					timestamping.update_TS_Recent_if_appropriate(SEG_TSval, SEG.SEQ)
				}
			}
		}
		
		// Processing Incoming Segments 4.1.
		macro_rules! check_sequence_number
		{
			($self: ident, $transmission_control_block: ident) =>
			{
				match $transmission_control_block.timestamping_reference()
				{
					None =>
					{
						check_sequence_number_r2!($self, $transmission_control_block);
						None
					}
				
					// RFC 7323, Section 3.2: "TSopt MUST be sent in every non-<RST> segment for the duration of the connection, and SHOULD be sent in an <RST> segment".
					Some(timestamping) => match $self.tcp_options.timestamps
					{
						Some(timestamps_option) =>
						{
							let (timestamping, SEG_TSval) = check_sequence_number_r1!(self, $transmission_control_block, timestamping, timestamps_options);
							
							check_sequence_number_r2!($self, $transmission_control_block);
							
							check_sequence_number_r3!($self, SEG_TSval);
							
							Some(timestamps)
						}
						
						None => if unlikely($self.reset_flag_set())
						{
							check_sequence_number_r2!($self, $transmission_control_block);
							
							None
						}
						else
						{
							invalid!($self, "TCP timestamps were negotiated; this segment, which does not have the Reset flag set, does not contain a timestamps option")
						},
					},
				}
			}
		}
		
		let SEG = self;
		let RCV = &mut transmission_control_block.RCV;
		let SND = &mut transmission_control_block.SND;
		
		match transmission_control_block.state()
		{
			SynchronizeSent => self.synchronize_sent(transmission_control_block),
			
			Established =>
			{
				let TrueWindow = SEG.WND << SND.Wind.Scale;
				
				let timestamps_option = check_sequence_number!(self, transmission_control_block);
				
				match SEG.syn_ack_fin_rst_only_flags()
				{
					Flags::Synchronize => self.received_synchronize_when_established(transmission_control_block),
					
					Flags::SynchronizeAcknowledgment => self.received_synchronize_acknowledgment_when_established(),
					
					Flags::Acknowledgment =>
						{
							if self.acknowledgment(transmission_control_block, timestamps_option)
							{
								return
							}
							self.data_in();
						}
					
					Flags::AcknowledgmentPush =>
						{
							if self.acknowledgment(transmission_control_block, timestamps_option)
							{
								return
							}
							self.data_in()
						}
					
					Flags::Finish =>
						{
							self.data_in();
							self.closewait()
						}
					
					Flags::FinishAcknowledgment =>
						{
							self.data_in();
							self.closewait()
						}
					
					Flags::FinishAcknowledgmentPush =>
						{
							self.data_in();
							self.closewait()
						}
					
					Flags::Reset | Flags::ResetAcknowledgment => self.received_reset(transmission_control_block),
					
					Flags::Push => self.data_in(),
					
					_ => invalid!(SEG, "In TCP state Established only Synchronize, SynchronizeAcknowledgment, Acknowledgment, AcknowledgmentPush, Finish, FinishAcknowledgment, FinishAcknowledgmentPush, Reset, ResetAcknowledgment and Push packets are allowed"),
				}
			}
			
			CloseWait =>
			{
				let timestamps_option = check_sequence_number!(self, transmission_control_block);
				
				match SEG.syn_ack_fin_rst_only_flags()
				{
					Flags::SynchronizeAcknowledgment => self.received_synchronize_acknowledgment_after_establishing_connection(transmission_control_block),
					
					Flags::Acknowledgment =>
					{
						if self.acknowledgment(transmission_control_block, timestamps_option)
						{
							return
						}
						if self.has_data()
						{
							self.established_or_later_send_reset(transmission_control_block)
						}
					}
					
					Flags::AcknowledgmentPush =>
					{
						if self.acknowledgment(transmission_control_block, timestamps_option)
						{
							return
						}
						self.established_or_later_send_reset(transmission_control_block)
					}
					
					Flags::Finish =>
					{
						if self.has_data()
						{
							self.established_or_later_send_reset(transmission_control_block)
						}
						self.closewait()
					}
					
					Flags::FinishAcknowledgment =>
					{
						if self.has_data()
						{
							self.established_or_later_send_reset(transmission_control_block)
						}
						self.closewait()
					}
					
					Flags::FinishAcknowledgmentPush =>
					{
						self.established_or_later_send_reset(transmission_control_block);
						self.closewait()
					}
					
					Flags::Reset => self.received_reset(transmission_control_block),
					
					Flags::Push => self.established_or_later_send_reset(transmission_control_block),
					
					_ => invalid!(SEG, "In TCP state CloseWait only SynchronizeAcknowledgment, Acknowledgment, AcknowledgmentPush, Finish, FinishAcknowledgment, FinishAcknowledgmentPush, Reset and Push packets are allowed"),
				}
			}
			
			LastAcknowledgment =>
			{
				let timestamps_option = check_sequence_number!(self, transmission_control_block);
				
				match SEG.syn_ack_fin_rst_only_flags()
				{
					Flags::SynchronizeAcknowledgment => self.received_synchronize_acknowledgment_after_establishing_connection(transmission_control_block),
					
					Flags::Acknowledgment =>
					{
						self.last_acknowledgment_wait(transmission_control_block);
						if self.has_data()
						{
							self.established_or_later_send_reset(transmission_control_block)
						}
					}
					
					Flags::AcknowledgmentPush =>
					{
						self.last_acknowledgment_wait(transmission_control_block);
						self.established_or_later_send_reset(transmission_control_block)
					}
					
					Flags::Finish => self.established_or_later_send_reset(transmission_control_block),
					
					Flags::FinishAcknowledgment => self.established_or_later_send_reset(transmission_control_block),
					
					Flags::FinishAcknowledgmentPush => self.established_or_later_send_reset(transmission_control_block),
					
					Flags::Reset => self.received_reset(transmission_control_block),
					
					Flags::Push => self.established_or_later_send_reset(transmission_control_block),
					
					_ => invalid!(SEG, "In TCP state LastAcknowledgment only SynchronizeAcknowledgment, Acknowledgment, AcknowledgmentPush, Finish, FinishAcknowledgment, FinishAcknowledgmentPush, Reset and Push packets are allowed"),
				}
			}
			
			FinishWait1 =>
			{
				let timestamps_option = check_sequence_number!(self, transmission_control_block);
				
				match SEG.syn_ack_fin_rst_only_flags()
				{
					Flags::SynchronizeAcknowledgment => self.received_synchronize_acknowledgment_after_establishing_connection(transmission_control_block),
					
					Flags::Acknowledgment =>
					{
						self.finish_wait_1_acknowledgment(transmission_control_block, timestamps_option);
						self.data_in();
					}
					
					Flags::AcknowledgmentPush =>
					{
						self.finish_wait_1_acknowledgment(transmission_control_block, timestamps_option);
						self.data_in()
					}
					
					Flags::Finish =>
					{
						self.data_in();
						self.finish_wait_1_finish(transmission_control_block)
					}
					
					Flags::FinishAcknowledgment =>
					{
						self.data_in();
						self.finish_acknowledgment(transmission_control_block)
					}
					
					Flags::FinishAcknowledgmentPush =>
					{
						self.data_in();
						self.finish_acknowledgment(transmission_control_block)
					}
					
					Flags::Reset => self.received_reset(transmission_control_block),
					
					Flags::Push => self.data_in(),
					
					_ => invalid!(SEG, "In TCP state FinishWait1 only SynchronizeAcknowledgment, Acknowledgment, AcknowledgmentPush, Finish, FinishAcknowledgment, FinishAcknowledgmentPush, Reset and Push packets are allowed"),
				}
			}
			
			FinishWait2 =>
			{
				let timestamps_option = check_sequence_number!(self, transmission_control_block);
				
				match SEG.syn_ack_fin_rst_only_flags()
				{
					Flags::SynchronizeAcknowledgment => self.received_synchronize_acknowledgment_after_establishing_connection(transmission_control_block),
					
					Flags::Acknowledgment =>
					{
						if self.acknowledgment(transmission_control_block, timestamps_option)
						{
							return
						}
						if self.has_data()
						{
							self.data_in()
						}
					}
					
					Flags::AcknowledgmentPush =>
					{
						if self.acknowledgment(transmission_control_block, timestamps_option)
						{
							return
						}
						self.data_in()
					}
					
					Flags::Finish =>
					{
						self.data_in();
						self.finish_wait_2_finish(transmission_control_block)
					}
					
					Flags::FinishAcknowledgment =>
					{
						self.data_in();
						self.finish_acknowledgment(transmission_control_block)
					}
					
					Flags::FinishAcknowledgmentPush =>
					{
						self.data_in();
						self.finish_acknowledgment(transmission_control_block)
					}
					
					Flags::Reset => self.received_reset(transmission_control_block),
					
					Flags::Push => self.data_in(),
					
					_ => invalid!(SEG, "In TCP state FinishWait2 only SynchronizeAcknowledgment, Acknowledgment, AcknowledgmentPush, Finish, FinishAcknowledgment, FinishAcknowledgmentPush, Reset and Push packets are allowed"),
				}
			}
			
			Closing =>
			{
				let timestamps_option = check_sequence_number!(self, transmission_control_block);
				
				match SEG.syn_ack_fin_rst_only_flags()
				{
					Flags::SynchronizeAcknowledgment => self.received_synchronize_acknowledgment_after_establishing_connection(transmission_control_block),
					
					Flags::Acknowledgment =>
					{
						self.closing_ack();
						if self.has_data()
						{
							self.established_or_later_send_reset(transmission_control_block)
						}
					}
					
					Flags::AcknowledgmentPush =>
					{
						self.closing_ack();
						self.established_or_later_send_reset(transmission_control_block)
					}
					
					Flags::Finish => self.established_or_later_send_reset(transmission_control_block),
					
					Flags::FinishAcknowledgment => self.established_or_later_send_reset(transmission_control_block),
					
					Flags::FinishAcknowledgmentPush => self.established_or_later_send_reset(transmission_control_block),
					
					Flags::Reset => self.received_reset(transmission_control_block),
					
					Flags::Push => self.established_or_later_send_reset(transmission_control_block),
					
					_ => invalid!(SEG, "In TCP state Closing only SynchronizeAcknowledgment, Acknowledgment, AcknowledgmentPush, Finish, FinishAcknowledgment, FinishAcknowledgmentPush, Reset and Push packets are allowed"),
				}
			}
			
			// TODO: https://tools.ietf.org/html/rfc6191 - Reducing the TIME-WAIT State Using TCP Timestamps
			TimeWait =>
			{
				let timestamps_option = check_sequence_number!(self, transmission_control_block);
				
				match SEG.syn_ack_fin_rst_only_flags()
				{
					Flags::SynchronizeAcknowledgment | Flags::Acknowledgment | Flags::AcknowledgmentPush | Flags::Finish | Flags::FinishAcknowledgment | Flags::FinishAcknowledgmentPush | Flags::Reset | Flags::Push => self.ignore(),
					
					_ => invalid!(SEG, "In TCP state TimeWait only SynchronizeAcknowledgment, Acknowledgment, AcknowledgmentPush, Finish, FinishAcknowledgment, FinishAcknowledgmentPush, Reset and Push packets are allowed"),
				}
			}
			
			Listen => unreachable_synthetic_state!("TCP state Listen is replaced with SYN flood defences 'process_for_synchronize'"),
			
			SynchronizeReceived => unreachable_synthetic_state!("TCP state SynchronizeReceived is replaced with SYN flood defences 'process_for_acknowledgment_of_syncookie'"),
			
			Closed => unreachable_synthetic_state!("TCP state Closed is never actually used"),
		}
	}
	
	#[inline(always)]
	fn has_data(&self) -> bool
	{
		self.payload_length != 0
	}
	
	#[inline(always)]
	fn payload_length(tcp_segment_length: usize, options_length: usize) -> usize
	{
		tcp_segment_length - size_of::<TcpFixedHeader>() - options_length
	}
}

/// Actions to take.
impl<'a, 'b, TCBA: TransmissionControlBlockAbstractions> ParsedTcpSegment<'a, 'b, TCBA>
{
	fn synchronize_sent(&self, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		let SEG = self;
		let RCV = &mut transmission_control_block.RCV;
		let SND = &mut transmission_control_block.SND;
		match SEG.syn_ack_fin_rst_only_flags()
		{
			// RFC 5961 Section 3.2: "If the RST bit is set and the sequence number exactly matches the next expected sequence number (RCV.NXT), then TCP MUST reset the connection".
			Flags::ResetAcknowledgment => if SEG.ACK == SND.NXT
			{
				transmission_control_block.error_connection_reset(self.interface)
			}
			else
			{
				invalid!(SEG, "TCP ResetAcknowledgment in violation of RFC 5961, possible RST attack")
			},
			
			// Processing Incoming Segments 3.1.1, 3.4.1
			Flags::SynchronizeAcknowledgment => if SND.UNA < SEG.ACK && SEG.ACK <= SND.NXT
			{
				RCV.NXT = SEG.SEQ + 1;
				RCV.processed = RCV.NXT;
				let IRS = SEG.SEQ;
				
				match self.tcp_options.maximum_segment_size
				{
					None => MaximumSegmentSizeOption::OriginalDefault,
					
					Some(their_maximum_segment_size) => min(their_maximum_segment_size, self.interface.our_current_maximum_segment_size_without_fragmentation(self.source_internet_protocol_address))
				}
				
				// Processing Incoming Segments 3.4.1.1.
				match self.tcp_options.window_scale
				{
					Some(window_scale_option) =>
					{
						SND.Wind.Scale = window_scale_option;
					}
					
					None =>
					{
						SND.Wind.Scale = WindowScaleOption::Zero;
						RCV.Wind.Scale = WindowScaleOption::Zero;
					}
				}
				
				// Processing Incoming Segments 3.4.1.1.
				match self.tcp_options.timestamps
				{
					Some(timestamps_option) =>
					{
						transmission_control_block.timestamping.as_ref().unwrap().borrow_mut().TS_Recent = timestamps_option.TSval;
					}
					
					None => transmission_control_block.timestamping = None, // TODO: does not work as not mutable.
				}
				
				if self.tcp_options.selective_acknowledgments_permitted
				{
					transmission_control_block.selective_acknowledgments_permitted = true; // TODO: does not work as not mutable.
				}
				
				SND.WND = SEG.WND << SND.Wind.Scale;
				SND.WL1 = SEG.SEQ;
				SND.WL2 = SEG.ACK;
				
				self.process_acceptable_acknowledgment(transmission_control_block, SND);
				transmission_control_block.set_state(State::Established);
				transmission_control_block.events_receiver.client_connection_established();
				
				// TODO: If using TCP Fast-Open, we can send data on the third part of the three-way handshake.
				// TODO: Thus we need to call data_in() before sending this ack.
				self.interface.send_acknowledgment(self.packet.take().unwrap(), transmission_control_block, Flags::Acknowledgment, SND.NXT, RCV.NXT);
				self.data_in();
			}
			else
			{
				ignore!(SEG, "TCP simultaneous open or invalid ACK ignored; Acknowledge or Reset not sent");
			},
			
			_ => ignore!(SEG, "TCP pure Resets, pure Acknowledgments and other technically valid oddities are ignored as they're likely to be spoofs, scans or attacks rather than errors"),
		}
	}
	
	
	fn received_synchronize_acknowledgment_when_established(&self)
	{
		// TODO: ? out of order ?
		
		if transmission_control_block.we_are_the_listener()
		{
			self.ignore()
		}
		else
		{
			let SEG = self;
			
			// TODO: The listener never got our first ACK
			
			xxx;
		}
	}
	
	fn received_synchronize_acknowledgment_after_establishing_connection(&self, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		// TODO: ? out of order ?
		
		if transmission_control_block.we_are_the_listener()
		{
			self.ignore()
		}
		else
		{
			let SEG = self;
			
			// TODO: The listener never got our first ACK, and anything subsequent... perhaps we should just give up at this point, or send a reset.
			
			xxx;
		}
	}
	
	#[inline(always)]
	fn process_acceptable_acknowledgment<'x>(&self, transmission_control_block: &TransmissionControlBlock<TCBA>, SND: RefMut<'x, TransmissionControlBlockSend>)
	{
		let SEG = self;
		
		debug_assert!(SND.UNA < SEG.ACK && SEG.ACK <= SND.NXT, "This is not an acceptable acknowledgment");
		
		// RFC 793, Page 72: "If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
		// Any segments on the retransmission queue which are thereby entirely acknowledged are removed."
		//
		// Processing Incoming Segments 3.4.1: "SND.UNA should be advanced to equal SEG.ACK (if there is an ACK), and any segments on the retransmission queue which are thereby acknowledged should be removed".
		let most_recent_segment_timestamp =
		{
			SND.UNA = SEG.ACK;
			transmission_control_block.remove_all_sent_segments_up_to(SND.UNA)
		};
		
		// RFC 7323, Section 4.1, RTTM Rule: "A TSecr value received in a segment MAY be used to update the averaged RTT measurement only if the segment advances the left edge of the send window, i.e., SND.UNA is increased".
		// RFC 6298, Section 3: "TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
		// That is, RTT samples MUST NOT be made using segments that were retransmitted".
		//
		// Since this function processes an acceptable acknowledgment only if SND.UNA < SEG.ACK, then it is safe to use this acknowledgment for a round trip time (RTT) measurement.
		if let Some(timestamp) = most_recent_segment_timestamp
		{
			match timestamps_option
			{
				Some(timestamps_option) => transmission_control_block.adjust_retransmission_time_out_based_on_timestamps(self.now, timestamps_option),
				
				None => transmission_control_block.adjust_retransmission_time_out_based_on_acknowledgments(self.now, timestamp),
			}
		}
		
		transmission_control_block.record_last_acknowledgment_occurred_at(self.now);
	}
	
	fn acknowledgment(&self, push_flag_set: bool, transmission_control_block: &TransmissionControlBlock<TCBA>, timestamps_option: Option<TimestampsOption>) -> bool
	{
		let SEG = self;
		let SND = &mut transmission_control_block.SND;
		
		if self.acceptable_acknowledgment(transmission_control_block)
		{
			self.process_acceptable_acknowledgment(transmission_control_block, SND);
			
			// TODO: Cancel / reset retrans timer if appropriate.
			// TODO: Cancel / reset keep-alive timer if appropriate.
			//TODO  USER TIMEOUT
			//
			//    For any state if the user timeout expires, flush all queues, signal
			//    the user "error:  connection aborted due to user timeout" in general
			//    and for any outstanding calls, delete the TCB, enter the CLOSED
			//    state and return.
			//
			//TODO  RETRANSMISSION TIMEOUT
			//
			//    For any state if the retransmission timeout expires on a segment in
			//    the retransmission queue, send the segment at the front of the
			//    retransmission queue again, reinitialize the retransmission timer,
			//    and return.
			//
			//TODO  TIME-WAIT TIMEOUT
			//
			//    If the time-wait timeout expires on a connection delete the TCB,
			//    enter the CLOSED state and return.
			
			
			
			
			// RFC 793, Page 72: "If SND.UNA < SEG.ACK =< SND.NXT, the send window should be updated".
			//
			// This is always true because this is an acceptable_acknowledgment().
			//
			// RFC 793, Page 72: "If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
			// ...
			// The [If] check [above] prevents [the use of] old segments to update the window".
			if SND.WL1 < SEG.SEQ || (SND.WL1 == SEG.SEQ && SND.WL2 <= SEG.ACK)
			{
				/// RFC 7323, Section 2.2, Page 9: "The window field in a segment where the SYN bit is set (i.e., a <SYN> or <SYN,ACK>) MUST NOT be scaled."
				///
				/// RFC 7323, Section 2.3, Page 9: "The window field (SEG.WND) in the header of every incoming segment, with the exception of <SYN> segments, MUST be left-shifted by Snd.Wind.Shift bits before updating SND.WND
				/// SND.WND = SEG.WND << Snd.Wind.Shift
				/// (assuming the other conditions of [RFC0793] are met, and using the "C" notation "<<" for left-shift)".
				SND.WND = SEG.WND << SND.Wind.Scale;
				SND.WL1 = SEG.SEQ;
				SND.WL2 = SEG.ACK;
			}
			false
		}
		// RFC 793, Page 72: "If the ACK is a duplicate (SEG.ACK < SND.UNA), it can be ignored"
		else if self.duplicate_acknowledgment(transmission_control_block)
		{
			self.ignore();
			false
		}
		// RFC 793, Page 72: "If the ACK acks something not yet sent (SEG.ACK > SND.NXT) then send an ACK, drop the segment, and return"
		else
		{
			debug_assert!(SEG.ACK > SND.NXT, "Condition for ACK for something not yet seen violated");
			
			self.interface.send_acknowledgment(transmission_control_block);
			true
		}
		
	fn data_in(&self, _push_flag_set: bool)
	{
		// SEE RFC 5961 Section 5: "Blind Data Injection Attack" mitigations.
		
		// TODO: ? out of order ?
		
		// TODO: If a segment's contents straddle the boundary between old and new, only the new parts should be processed.
		
		/*
		
		Once the TCP takes responsibility for the data it advances
				RCV.NXT over the data accepted, and adjusts RCV.WND as
				apporopriate to the current buffer availability.  The total of
				RCV.NXT and RCV.WND should not be reduced.
		*/
// Should only be done on receipt of segment data, apparently, not ack - RFC 793 page 74.
		// and only in ESTABLISHED STATE
		//      FIN-WAIT-1 STATE
		//      FIN-WAIT-2 STATE
//			{
//				let RCV = transmission_control_block.RCV;
//				RCV.WND = SEG.WND() << RCV.Wind.Scale;
//			}
	}
	
	fn closing_ack(&self, _push_flag_set: bool)
	{
		// TODO: ? out of order ?
		
	}
	
	fn closewait(&self, _push_flag_set: bool)
	{
		// TODO: ? out of order ?
		
		In addition to the processing for the ESTABLISHED state, if
	the ACK acknowledges our FIN then enter the TIME-WAIT state,
		otherwise ignore the segment.
	}
	
	/// Typically this occurs because a connection attempt retransmitted a Synchronize packet.
	fn received_synchronize_when_established(&self, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		// TODO: ? out of order ?
		
		self.interface.send_acknowledgment(transmission_control_block);
	}
	
	fn finish_wait_1_acknowledgment(&self, push_flag_set: bool, transmission_control_block: &TransmissionControlBlock<TCBA>, timestamps: Option<TimestampsOption>)
	{
		// TODO: ? out of order ?
		
		if self.acknowledgment(push_flag_set, transmission_control_block, timestamps)
		{
			return
		}
		
		let SEG = self;
		let SND = &mut transmission_control_block.SND;
		
		if SEG.ACK == (SND.NXT - 1)
		{
			transmission_control_block.set_state(State::FinishWait2)
		}
		else
		{
			invalid!(SEG, "TCP segment in finish_wait_1_acknowledgment was not valid")
		}
	}
	
	fn finish_wait_2_finish(&self, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		// TODO: ? out of order ?
		
		In addition to the processing for the ESTABLISHED state, if
	the retransmission queue is empty, the user's CLOSE can be
		acknowledged ("ok") but do not delete the TCB.
		
		let SEG = self;
		let mut RCV = &mut transmission_control_block.RCV;
		
		RCV.NXT = SEG.SEQ + 1;
		
		transmission_control_block.begin_time_wait(self.interface)
	}
	
	fn last_acknowledgment_wait(&self, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		// TODO: ? out of order ?
		
		let SEG = self;
		let SND = &mut transmission_control_block.SND;
		
		let valid = SEG.ACK == SND.NXT;
		
		if valid
		{
			transmission_control_block.close(self.interface);
		}
		else
		{
			invalid!(SEG, "TCP segment in last_acknowledgment_wait was invalid")
		}
	}
	
	fn established_or_later_send_reset(&self, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		let SEG = self;
		self.interface.send_reset(self.packet.take().unwrap(), transmission_control_block, SEG.ACK);
	}
	
	fn finish_wait_1_finish(&self, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		// TODO: ? out of order ?
		
		transmission_control_block.set_state(State::Closing);
		
		let mut RCV = &mut transmission_control_block.RCV;
		
		RCV.processed = RCV.NXT + 1;
		RCV.NXT += 1;
		
		self.interface.send_acknowledgment(transmission_control_block);
	}
	
	fn finish_acknowledgment(&self, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		// TODO: ? out of order ?
		
		let mut RCV = &mut transmission_control_block.RCV;
		
		RCV.NXT += 1;
		
		transmission_control_block.begin_time_wait(self.interface)
	}
	
	/// Implementation is as RFC 5961 Section 3.2 rather than RFC 793.
	///
	/// This is [Snellman](https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/) Case B 'RST-REPLY'.
	fn received_reset(&self, transmission_control_block: &TransmissionControlBlock<TCBA>)
	{
		// RFC 5961 Section 3.2 Page 8:-
		// "In all states except SYN-SENT, all reset (RST) packets are validated by checking their SEQ-fields [sequence numbers].
		// A reset is valid if its sequence number exactly matches the next expected sequence number.
		// If the RST arrives and its sequence number field does NOT match the next expected sequence number but is within the window, then the receiver should generate an ACK \*.
		// In all other cases, where the SEQ-field does not match and is outside the window, the receiver MUST silently discard the segment."
		//
		// \* This is known as a 'Challenge ACK'.
		
		let RCV = &transmission_control_block.RCV;
		let SEG = self;
		
		let segment_sequence_number_exactly_matches_next_expected_sequence_number = SEG.SEQ == RCV.NXT;
		
		if segment_sequence_number_exactly_matches_next_expected_sequence_number
		{
			transmission_control_block.forcibly_close(self.interface);
		}
		else
		{
			// `RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND`.
			let reset_is_within_window = RCV.NXT <= SEG.SEQ && SEG.SEQ < RCV.NXT + RCV.WND();
			
			if reset_is_within_window
			{
				self.interface.send_challenge_acknowledgment(self.packet.take().unwrap(), transmission_control_block);
			}
			else
			{
				invalid!(SEG, "TCP Reset received by state SynchronizeSent with unacceptable acknowledgment value")
			}
		}
	}
	
	#[inline(always)]
	fn ignore(&self)
	{
		invalid!(self, "TCP segment ignored")
	}
}

/// Supporting logic.
impl<'a, 'b, TCBA: TransmissionControlBlockAbstractions> ParsedTcpSegment<'a, 'b, TCBA>
{
	/// RFC 793, page 25: "A new acknowledgment (called an "acceptable ack"), is one for which the inequality `SND.UNA < SEG.ACK =< SND.NXT` holds".
	///
	/// RFC 793, page 25: "A segment on the retransmission queue is fully acknowledged if the sum of its sequence number and length is less or equal than the acknowledgment value in the incoming segment."
	#[inline(always)]
	fn acceptable_acknowledgment(&self, transmission_control_block: &TransmissionControlBlock) -> bool
	{
		let SND = &transmission_control_block.SND;
		let SEG = self;
		
		SND.UNA < SEG.ACK && SEG.ACK <= SND.NXT
	}
	
	/// RFC 793, Page 72: "If the ACK is a duplicate (SEG.ACK < SND.UNA), it can be ignored"
	#[inline(always)]
	fn duplicate_acknowledgment(&self, transmission_control_block: &TransmissionControlBlock) -> bool
	{
		let SND = &transmission_control_block.SND;
		let SEG = self;
		
		SEG.ACK < SND.UNA
	}
	
	/// RFC 793, page 25: "Last sequence number occupied by the incoming segment".
	#[inline(always)]
	fn last_sequence_number_occupied_by_the_incoming_segment(&self) -> WrappingSequenceNumber
	{
		let SEG = self;
		
		SEG.SEQ + SEG.LEN - 1
	}
	
	/// RFC 793 page 25: "A segment is judged to occupy a portion of valid receive sequence space ... Due to zero windows and zero length segments, we have four cases for the acceptability of an incoming segment".
	#[inline(always)]
	fn segment_is_acceptable_because_it_occupies_a_portion_of_valid_receive_sequence_space(&self, transmission_control_block: &TransmissionControlBlock<TCBA>) -> bool
	{
		let SEG = self;
		let RCV = &transmission_control_block.RCV;
		
		// See Processing Incoming Segments 4.1.2 (based on RFC 793 Page 69).
		// Specifically, the Table 4.1 "Tests for Acceptability of an Incoming Segment".
		if SEG.LEN == 0
		{
			if RCV.WND == WindowSize::Zero
			{
				SEG.SEQ == RCV.NXT
			}
			else
			{
				RCV.NXT <= SEG.SEQ && SEG.SEQ < RCV.NXT + RCV.WND
			}
		}
		else
		{
			if RCV.WND == WindowSize::Zero
			{
				self.reset_flag_set()
			}
			else
			{
				(RCV.NXT <= SEG.SEQ && SEG.SEQ < RCV.NXT + RCV.WND) || (RCV.NXT <= SEG.SEQ + SEG.LEN - 1 && SEG.SEQ + SEG.LEN - 1 < RCV.NXT + RCV.WND)
			}
		}
	}
	
	#[inline(always)]
	fn payload_data_pointer(&self) -> NonNull<u8>
	{
		self.SEG.payload_data_pointer(self.options_length)
	}
	
	#[inline(always)]
	pub(crate) fn source_port_destination_port(&self) -> SourcePortDestinationPort
	{
		self.SEG.source_port_destination_port()
	}
	
	#[inline(always)]
	pub(crate) fn remote_port_local_port(&self) -> RemotePortLocalPort
	{
		self.source_port_destination_port().remote_port_local_port()
	}
}
