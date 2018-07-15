// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A Transmission Control Block (TCB) which is the 'the data structure that records the state of a connection' (RFC 793, Glossary, Page 84).
#[derive(Debug)]
pub(crate) struct TransmissionControlBlock<TCBA: TransmissionControlBlockAbstractions>
{
	/// This duplicates information already held in the HashMap of transmission_control_blocks in Interface.
	///
	/// It is here also as this data is needed when removing a transmission_control_block from an alarm (eg user_time_out); when removing in other circumstances, the information is available from the incoming SEG.
	key: TransmissionControlBlockKey<TCBA::Address>,
	
	state: State,
	RCV: TransmissionControlBlockReceive,
	SND: TransmissionControlBlockSend,
	
	events_receiver: <<TCBA as TransmissionControlBlockAbstractions>::EventsReceiverCreator as TransmissionControlBlockEventsReceiverCreator>::EventsReceiver,
	
	keep_alive_alarm: Alarm<KeepAliveAlarmBehaviour<TCBA>, TCBA>,
	retransmission_and_zero_window_probe_alarm: Alarm<RetransmissionAndZeroWindowProbeAlarmBehaviour<TCBA>, TCBA>,
	user_time_out_alarm: Alarm<UserTimeOutAlarmBehaviour<TCBA>, TCBA>,
	
	timestamping: Option<Timestamping>,
	
	explicit_congestion_notification_state: Option<ExplicitCongestionNotificationState>,
	
	we_are_the_listener: bool,
	
	/// Also known as "MSS".
	///
	/// RFC 793 confusingly uses 'segment size' and 'segment length' interchangeably.
	///
	/// RFC 793: "If this option is present, then it communicates the maximum receive segment size at the TCP which sends this segment".
	///
	/// RFC 6691, Section 2: "When calculating the value to put in the TCP MSS option, the MTU value SHOULD be decreased by only the size of the fixed IP and TCP headers and SHOULD NOT be decreased to account for any possible IP or TCP options".
	maximum_segment_size_to_send_to_remote: u16,
	
	/// This value is uninitialized until the state becomes established.
	selective_acknowledgments_permitted: bool,
	
	/// This value is always known but may not be in use.
	md5_authentication_key: Option<Rc<Md5PreSharedSecretKey>>,

	congestion_control: CongestionControl,
}

/// New connections and related functionality.
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	#[inline(always)]
	pub(crate) fn new_for_closed_to_synchronize_sent(interface: &Interface<TCBA>, remote_internet_protocol_address: TCBA::Address, remote_port_local_port: RemotePortLocalPort, now: MonotonicMillisecondTimestamp, ISS: WrappingSequenceNumber, explicit_congestion_notification_supported: bool)
	{
		let maximum_segment_size = interface.our_current_maximum_segment_size_without_fragmentation(&remote_internet_protocol_address);
		
		let cached_congestion_data = interface.cached_congestion_data(&remote_internet_protocol_address);
		
		let key = TransmissionControlBlockKey::for_client(remote_internet_protocol_address, for_client);
		
		let md5_authentication_key = interface.find_md5_authentication_key(remote_internet_protocol_address, remote_port_local_port).map(|key_reference| key_reference.clone());
		
		Self
		{
			events_receiver: TCBA::EventReceiverCreator::create(&key),
			key,
			state: State::SynchronizeSent,
			RCV: TransmissionControlBlockReceive::new_for_closed_to_synchronize_sent(),
			SND: TransmissionControlBlockSend::new_for_closed_to_synchronize_sent(interface, now, ISS),
			keep_alive_alarm: Default::default(),
			retransmission_and_zero_window_probe_alarm: Alarm::new(RetransmissionAndZeroWindowProbeAlarmBehaviour::new(&cached_congestion_data, true)),
			user_time_out_alarm: Default::default(),
			timestamping: Timestamping::new_for_closed_to_synchronize_sent(),
			explicit_congestion_notification_state: if explicit_congestion_notification_supported
			{
				Some(Default::default())
			}
			else
			{
				None
			},
			we_are_the_listener: false,
			maximum_segment_size_to_send_to_remote: maximum_segment_size,
			selective_acknowledgments_permitted: false,
			md5_authentication_key,
			congestion_control: CongestionControl::new(Self::InitialCongestionWindowAlgorithm, MonotonicMillisecondDuration::Zero, maximum_segment_size, &cached_congestion_data),
		}
	}
	
	#[inline(always)]
	pub(crate) fn new_for_sychronize_received_to_established(interface: &Interface<TCBA>, source_internet_protocol_address: &TCBA::Address, SEG: &ParsedTcpSegment, tcp_options: &TcpOptions, parsed_syncookie: ParsedSynCookie, now: MonotonicMillisecondTimestamp, md5_authentication_key: Option<Rc<Md5PreSharedSecretKey>>) -> Self
	{
		let remote_internet_protocol_address = source_internet_protocol_address;
		
		let cached_congestion_data = interface.cached_congestion_data(now, &remote_internet_protocol_address);
		
		let key = TransmissionControlBlockKey::from_incoming_segment(remote_internet_protocol_address, SEG.SEG);
		
		let SEG_WND = SEG.WND();
		
		let (RCV_WND, RCV_Wind_Shift, SND_WND, SND_Wind_Shift) = match parsed_syncookie.their_window_scale
		{
			None => (InitialWindowSize::Segment << WindowScaleOption::EquivalentToNoWindowScale, WindowScaleOption::EquivalentToNoWindowScale, SEG_WND << WindowScaleOption::EquivalentToNoWindowScale, WindowScaleOption::EquivalentToNoWindowScale),
			
			Some(SND_Wind_Scale) =>
			{
				(InitialWindowSize::Segment << InitialWindowSize::Shift, InitialWindowSize::Shift, SEG_WND << SND_Wind_Scale, SND_Wind_Scale)
			}
		};
		
		// Original SYNACK segment SEQ.ACK().
		let ISS = parsed_syncookie.ISS;
		
		// Original SYN segment SEQ.SEQ().
		let IRS = parsed_syncookie.IRS;
		
		let RCV_NXT = IRS + 1;
		
		let maximum_segment_size = Self::maximum_segment_size_to_send_to_remote_u16(parsed_syncookie.their_maximum_segment_size, interface, remote_internet_protocol_address);
		let selective_acknowledgments_permitted = parsed_syncookie.their_selective_acknowledgment_permitted;
		let timestamping = Timestamping::new_for_sychronize_received_to_established(tcp_options, now, RCV_NXT);
		let supports_timestamping = timestamping.is_some();
		
		Self
		{
			events_receiver: TCBA::EventReceiverCreator::create(&key),
			key,
			state: State::Established,
			RCV: TransmissionControlBlockReceive::new_for_sychronize_received_to_established(RCV_NXT, RCV_WND, RCV_Wind_Shift),
			SND: TransmissionControlBlockSend::new_for_sychronize_received_to_established(interface, now, ISS, IRS, SND_WND, SND_Wind_Shift),
			keep_alive_alarm: Default::default(),
			retransmission_and_zero_window_probe_alarm: Alarm::new(RetransmissionAndZeroWindowProbeAlarmBehaviour::new(&cached_congestion_data, false)),
			user_time_out_alarm: Default::default(),
			timestamping,
			explicit_congestion_notification_state: if parsed_syncookie.explicit_congestion_notification_supported
			{
				Some(Default::default())
			}
			else
			{
				None
			},
			we_are_the_listener: true,
			maximum_segment_size_to_send_to_remote: maximum_segment_size,
			selective_acknowledgments_permitted,
			md5_authentication_key,
			congestion_control: CongestionControl::new(Self::InitialCongestionWindowAlgorithm, now, maximum_segment_size, &cached_congestion_data),
		}
	}
	
	#[inline(always)]
	pub(crate) fn our_offered_maximum_segment_size_when_initiating_connections(&self) -> MaximumSegmentSizeOption
	{
		debug_assert!(!self.we_are_the_listener, "We are the listener (server)");
		
		MaximumSegmentSizeOption::from(self.maximum_segment_size_to_send_to_remote)
	}
	
	#[inline(always)]
	pub(crate) fn acknowledgment_of_new_data_returning_true_if_failed(&mut self, interface: &Interface<TCBA>, SEG: &ParsedTcpSegment<TCBA>, now: MonotonicMillisecondTimestamp, timestamps_option: Option<&TimestampsOption>, explicit_congestion_echo: bool) -> bool
	{
		// TODO: RFC 6298 Section 5: "(5.1) Every time a packet containing data is sent (including a retransmission), if the timer is not running, start it running so that it will expire after RTO seconds (for the current value of RTO)
		//
		// This advice can also be interpreted for zero-window probes.
		x;
		
		
		self.SND.update_window(SEG, now);
		let (bytes_acknowledged, unretransmitted_segment_timestamp, a_window_of_data_was_processed, explicit_congestion_echo) = self.SND.move_UNA(SEG, explicit_congestion_echo);
		
		// RFC 5681 Section 3.2 Paragraph 2: "The fast retransmit algorithm uses the arrival of 3 duplicate ACKs (as defined in section 2, without any intervening ACKs which move SND.UNA) as an indication that a segment has been lost.
		// After receiving 3 duplicate ACKs, TCP performs a retransmission of what appears to be the missing segment, without waiting for the retransmission timer to expire".
		//
		// This implies that an acceptable acknowledgment, which does move SND.UNA, resets the duplicate acknowledgment count.
		self.congestion_control.reset_duplicate_acknowledgment_count();
		
		// RFC 6298 Section 3: "TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
		// That is, RTT samples MUST NOT be made using segments that were retransmitted
		// ...
		// A TCP implementation MUST take at least one RTT measurement per RTT (unless that is not possible per Karn's algorithm)".
		if let Some(fully_acknowledged_segment_timestamp) = unretransmitted_segment_timestamp
		{
			if a_window_of_data_was_processed
			{
				self.compute_a_new_estimate_of_round_trip_time_for_a_fully_acknowledged_segment(now, fully_acknowledged_segment_timestamp, timestamps_option);
			}
		}
		
		self.increase_bytes_acknowledged(bytes_acknowledged);
		
		// RFC 3168 Section 6.1.2 Paragraph 2: "TCP should not react to congestion indications more than once every window of data (or more loosely, more than once every round-trip time).
		// That is, the TCP sender's congestion window should be reduced only once in response to a series of dropped and/or CE packets from a single window of data.
		// In addition, the TCP source should not decrease the slow-start threshold, ssthresh, if it has been decreased within the last round trip time".
		if let Some(explicit_congestion_notification_state) = transmission_control_block.explicit_congestion_notification_state()
		{
			if a_window_of_data_was_processed && explicit_congestion_echo
			{
				explicit_congestion_notification_state.incoming_data_packet_had_explicit_congestion_echo_flag_set();
				
				// TODO: RFC 3168 6.1.2 Paragraph 3: "... the sending TCP MUST reset the retransmit timer on receiving the ECN-Echo packet when the congestion window is one".
				//
				// \* A congestion window of one (1) means `cwnd` is 1 x (Sending) MSS.
				//
				// This RFC was written before appropriate byte counting, so we interpret this as 1 x Sending Maximum Segment Size (SMSS or Sending MSS); since this is in bytes, we more liberally interpet one as "less than or equal to SMSS").
				if self.congestion_control.congestion_window_is_one()
				{
					self.cancel_retransmission_and_zero_window_probe_alarm(interface.alarms());
				}
			}
		}
		
		if self.all_data_acknowledged()
		{
			if self.send_window_is_zero()
			{
				if unlikely!(self.send_zero_window_probe_returning_true_if_failed(interface, now, true))
				{
					return true;
				}
			}
			else
			{
				// TODO: we have some space to send some data after ACKing. We may have data buffered but not sent, eg due to SND.WND or congestion control.
				// But see RFC 5681 - and whether we're allowed to.
				// self.SND.data_buffered_but_not_transmitted()
			}
		}
		else
		{
			// TODO: we have some space to send some data after ACKing. We may have data buffered but not sent, eg due to SND.WND or congestion control.
			// But see RFC 5681 - and whether we're allowed to.
			// self.SND.data_buffered_but_not_transmitted()
		}
		
		// TODO: Waking up for write() (or close)
		// We ought to wake up the sender every time we ack data, as it creates send buffer space.
		// This could be inefficient if not using LRO / GRO, so we may want a combined 'last woke up' / 'minimum data space available'
		// We could combine this with small window / slow send to try to defeat slowloris like attacks.
		// RFC 5681 Section 4.1: "TCP SHOULD set cwnd to no more than RW (the restart window) before beginning transmission if the TCP has not sent data in an interval exceeding the retransmission timeout".
		// self.congestion_control.last_sent_data_at(now);
		
		// RFC 6296 Section 5: "An implementation MUST manage the retransmission timer(s) in such a way that a segment is never retransmitted too early, i.e., less than one RTO after the previous transmission of that segment".
		//
		// RFC 6298 Section 5: "(5.3) When an ACK is received that acknowledges new data, restart the retransmission timer so that it will expire after RTO seconds (for the current value of RTO)".
		//
		// RFC 6298 Section 5: "(5.2) When all outstanding data has been acknowledged, turn off the retransmission timer".
		//
		// RFC 1122 Section 4.2.2.17: hints that we should turn-on the zero window probe timer when all outstanding data has been acknowledged and the send window is zero.
		
		// TODO: Post-FIN, we no longer send zero window probes.
		self.schedule_or_cancel_retransmission_and_zero_window_probe_alarm_as_appropriate(interface.alarms());
		
		// TODO: do we do an immediate re-transmit here for all packets in the retransmit queue whose timestamp exceeds the RTO before starting the timer?
		// ie go through retransmit queue, check for packets (originally transmitted - now) >= RTO, resend; set the timer for ((originally transmitted) + RTO) for the first packet otherwise. This will handle stretch ACKs and TSO better I think.
		
		false
	}
	
	#[inline(always)]
	pub(crate) fn RECEIVE(&mut self, interface: &Interface<TCBA>)
	{
		use self::State::*;
		
		match self.state()
		{
			Closed => unreachable_synthetic_state!("TCP state Closed is never actually used"),
			
			Listen => unreachable_synthetic_state!("TCP state Listen is replaced with SYN flood defences"),
			
			SynchronizeSent =>
			{
				// TODO: Queue data.
			}
			
			SynchronizeReceived => unreachable_synthetic_state!("TCP state SynchronizeReceived is replaced with SYN flood defences"),
			
			Established | FinishWait1 | FinishWait2 =>
			{
				// TODO: OK
			}
			
			CloseWait =>
			{
				// TODO: Error connection closing if nothing left to pass to receive
			}
			
			Closing | LastAcknowledgment | TimeWait =>
			{
				// TODO: Error connection closing
			}
		}
	}
	
	#[inline(always)]
	pub(crate) fn CLOSE(&mut self, interface: &Interface<TCBA>, now: MonotonicMillisecondTimestamp)
	{
		use self::State::*;
		
		match self.state()
		{
			Closed => unreachable_synthetic_state!("TCP state Closed is never actually used"),
			
			Listen => unreachable_synthetic_state!("TCP state Listen is replaced with SYN flood defences"),
			
			SynchronizeSent => self.closed(interface, now),
			
			SynchronizeReceived => unreachable_synthetic_state!("TCP state SynchronizeReceived is replaced with SYN flood defences"),
			
			Established =>
			{
				// RFC 793 Section 3.7 Page 60: "Queue this until all preceding SENDs have been segmentized, then form a FIN segment and send it.
				// In any case, enter FIN-WAIT-1 state".
			}
			
			FinishWait1 | FinishWait2 =>
			{
				// RFC 793 Section 3.7 Page 60: "Strictly speaking, this is an error and should receive a "error: connection closing" response.
				// An "ok" response would be cceptable, too, as long as a second FIN is not emitted (the firstFIN may be retransmitted though)".
			}
			
			CloseWait =>
			{
				//  RFC 793 Section 3.7 Page 60: "Queue this request until all preceding SENDs have been segmentized; then send a FIN segment, enter CLOSING state".
				// TODO: Error connection closing if nothing left to pass to receive
			}
			
			Closing | LastAcknowledgment | TimeWait =>
			{
				// TODO: Error connection closing
			}
		}
	}
}

/// Connection Identification ('key').
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	#[inline(always)]
	pub(crate) fn remote_internet_protocol_address(&self) -> &TCBA::Address
	{
		self.key.remote_internet_protocol_address()
	}
	
	#[inline(always)]
	pub(crate) fn remote_port_local_port(&self) -> RemotePortLocalPort
	{
		self.key.remote_port_local_port()
	}
	
	#[inline(always)]
	pub(crate) fn we_are_the_listener(&self) -> bool
	{
		self.we_are_the_listener
	}
}

/// Maximum segment size.
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	#[inline(always)]
	pub(crate) fn maximum_segment_size_to_send_to_remote<TCBA: TransmissionControlBlockAbstractions>(their_maximum_segment_size_options: Option<MaximumSegmentSizeOption>, interface: &Interface<TCBA>, remote_internet_protocol_address: &TCBA::Address) -> u16
	{
		let maximum_segment_size_option = match their_maximum_segment_size_options
		{
			None => TCBA::Address::DefaultMaximumSegmentSizeIfNoneSpecified,
			
			Some(their_maximum_segment_size_option) => their_maximum_segment_size_option.0,
		};
		
		Self::maximum_segment_size_to_send_to_remote_u16(maximum_segment_size_option.to_native_endian(), interface, remote_internet_protocol_address)
	}
	
	#[inline(always)]
	fn maximum_segment_size_to_send_to_remote_u16<TCBA: TransmissionControlBlockAbstractions>(their_maximum_segment_size: u16, interface: &Interface<TCBA>, remote_internet_protocol_address: &TCBA::Address) -> u16
	{
		min(their_maximum_segment_size, interface.our_current_maximum_segment_size_without_fragmentation(remote_internet_protocol_address))
	}
}

/// State change.
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	/// RFC 793 Section 3.7 ABORT Call Page 62.
	#[inline(always)]
	pub(crate) fn abort(&mut self, interface: &Interface<TCBA>, now: MonotonicMillisecondTimestamp) -> Option<TickDuration>
	{
		use self::State::*;
		
		match self.state()
		{
			Closed => unreachable_synthetic_state!("TCP state Closed is never actually used"),
			
			Listen => unreachable_synthetic_state!("TCP state Listen is replaced with SYN flood defences"),
			
			SynchronizeSent => self.aborted(interface, now),
			
			SynchronizeReceived => unreachable_synthetic_state!("TCP state SynchronizeReceived is replaced with SYN flood defences 'process_for_acknowledgment_of_syncookie'"),
			
			Established | FinishWait1 | FinishWait2 | CloseWait =>
			{
				interface.send_reset_without_packet_to_reuse(self, now, transmission_control_block.SND.NXT);
				self.aborted(interface, now)
			}
			
			Closing | LastAcknowledgment => self.aborted(interface, now),
			
			TimeWait => self.closed(interface, now.to_milliseconds()),
		}
		
		None
	}
	
	#[inline(always)]
	fn closed(&mut self, interface: &Interface<TCBA>, now: MonotonicMillisecondTimestamp)
	{
		self.events_receiver.closed();
		interface.destroy_transmission_control_block(&self.key)
	}
	
	#[inline(always)]
	pub(crate) fn aborted(&mut self, interface: &Interface<TCBA>, now: MonotonicMillisecondTimestamp)
	{
		self.events_receiver.aborted();
		interface.destroy_transmission_control_block(&self.key)
	}
	
	#[inline(always)]
	pub(crate) fn destroying(self, alarms: &Alarms<TCBA>)
	{
		self.keep_alive_alarm.cancel(alarms);
		self.retransmission_and_zero_window_probe_alarm.cancel(alarms);
		self.user_time_out_alarm.cancel(alarms);
	}
}

/// Transmission
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	#[inline(always)]
	pub(crate) fn maximum_payload_size_excluding_synchronize_and_finish(&mut self, now: MonotonicMillisecondTimestamp, padded_options_size: usize) -> u32
	{
		min(self.maximum_data(now), self.maximum_segment_payload_size(padded_options_size))
	}
	
	#[inline(always)]
	fn maximum_data(&mut self, now: MonotonicMillisecondTimestamp) -> u32
	{
		self.congestion_control.reset_congestion_window_to_restart_window_if_no_data_sent_for_an_interval_exceeding_the_retransmission_time_out(now, self.explicit_congestion_notification_state(), self.retransmission_time_out());
		
		self.congestion_control.maximum_data(self.SND.rwnd())
	}
	
	#[inline(always)]
	fn maximum_segment_payload_size(&mut self, padded_options_size: usize) -> u32
	{
		self.maximum_segment_size_to_send_to_remote - ((size_of::<TcpFixedHeader>() + padded_options_size) as u32)
	}
	
	#[inline(always)]
	pub(crate) fn SEND<DataWriter: Fn(&mut [u8]) -> usize>(&mut self, interface: &Interface<TCBA>, data_writer: DataWriter, now: MonotonicMillisecondTimestamp)
	{
		use self::State::*;
		
		match self.state()
		{
			Closed => unreachable_synthetic_state!("TCP state Closed is never actually used"),
			
			Listen => unreachable_synthetic_state!("TCP state Listen is replaced with SYN flood defences"),
			
			SynchronizeSent => self.SND.buffer_data_to_send(data_writer),
			
			SynchronizeReceived => unreachable_synthetic_state!("TCP state SynchronizeReceived is replaced with SYN flood defences 'process_for_acknowledgment_of_syncookie'"),
			
			Established | CloseWait =>
			{
				self.SND.buffer_data_to_send(data_writer);
				
				let mut maximum_data = Bytes(self.maximum_data(now));
				
				/*
					Create an rte_mbuf chain
						- header
						- data (one or two) [upto self.maximum_segment_payload_size() for each segment]
						- header
						- data (one or two)
						- etc
					
					
					Create 'packet' objects.
					Need one packet for header, one for payload, potentially one extra for payload if using physical addressing.
				
				if (unsafe { rte_eal_iova_mode() } == rte_iova_mode::RTE_IOVA_VA)
				{
				}
				
				magic_ring_buffer.read_buffer_slice() or magic_ring_buffer.physical_read_buffers_slice()
				
				*/
				
				self.SND.magic_ring_buffer.read_buffer_slice(maximum_data);
				self.SND.magic_ring_buffer.physical_read_buffers_slice(maximum_data);
				
				
				
				
				
				
				
				
				
				
				DDDDDD
				
				
				
				
				
				
				
				
				
				self.data_to_transmit_commit(total_sent);
				
				// How much data can we transmit?
				if self.SND.retransmission_queue_is_not_full()
				{
					// what's the cwnd budget?
					
					// it's a case of filling segments..
				}
				
				// populate self.congestion_control.last_sent_data_at = now;
				xxx;
			}
			
			FinishWait1 | FinishWait2 | Closing | LastAcknowledgment | TimeWait => panic!("Connection closing"),
		}
	}
	
	
	#[inline(always)]
	pub(crate) fn transmitted(&mut self, now: MonotonicMillisecondTimestamp, starts_at: SequenceNumber, data_length_excluding_length_of_synchronize_and_finish_controls: u32, flags: Flags)
	{
		unless synchronize,
		flags.remove(Flags::CongestionWindowReduced | Flags::ExplicitCongestionEcho)
	
	
		self.SND.transmitted(now, starts_at, data_length_excluding_length_of_synchronize_and_finish_controls, flags)
		
		xxx;
	}
}

/// Congestion Control.
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	const InitialCongestionWindowAlgorithm: InitialCongestionWindowAlgorithm = InitialCongestionWindowAlgorithm::RFC_6928;
	
	#[inline(always)]
	pub(crate) fn increment_duplicate_acknowledgments_received_without_any_intervening_acknwoledgments_which_moved_SND_UNA(&mut self)
	{
		self.congestion_control.increment_duplicate_acknowledgments_received_without_any_intervening_acknwoledgments_which_moved_SND_UNA()
	}
	
	#[inline(always)]
	pub(crate) fn reset_congestion_window_to_restart_window_because_no_data_received_after_connection_became_idle(&mut self)
	{
		self.congestion_control.reset_congestion_window_to_restart_window_because_no_data_received_after_connection_became_idle()
	}
	
	#[inline(always)]
	pub(crate) fn reset_congestion_window_to_loss_window_because_retransmission_timed_out(&mut self)
	{
		self.congestion_control.reset_congestion_window_to_loss_window_because_retransmission_timed_out(self.explicit_congestion_notification_state())
	}
	
	#[inline(always)]
	pub(crate) fn bytes_sent_in_payload_in_a_segment_which_is_not_a_zero_window_probe_or_retransmission(&mut self, increase_flight_size_by_amount_of_bytes: u32)
	{
		self.congestion_control.bytes_sent_in_payload_in_a_segment_which_is_not_a_zero_window_probe_or_retransmission(increase_flight_size_by_amount_of_bytes)
	}
	
	#[inline(always)]
	pub(crate) fn rfc_5681_section_7_paragaph_6_set_ssthresh_to_half_of_flight_size_on_first_retransmission(&mut self)
	{
		self.congestion_control.rfc_5681_section_7_paragaph_6_set_ssthresh_to_half_of_flight_size_on_first_retransmission();
	}
	
	#[inline(always)]
	fn increase_bytes_acknowledged(&mut self, by_amount_of_bytes: u32)
	{
		self.congestion_control.increase_bytes_acknowledged(by_amount_of_bytes)
	}
}

/// Explicit Congestion Notification.
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	#[inline(always)]
	pub(crate) fn explicit_congestion_notification_unsupported(&self) -> bool
	{
		self.explicit_congestion_notification_state.is_none()
	}
	
	#[inline(always)]
	pub(crate) fn explicit_congestion_notification_supported(&self) -> bool
	{
		self.explicit_congestion_notification_state.is_some()
	}
	
	#[inline(always)]
	pub(crate) fn disable_explicit_congestion_notification(&mut self)
	{
		self.explicit_congestion_notification_state = None;
	}
	
	#[inline(always)]
	pub(crate) fn explicit_congestion_notification_state(&mut self) -> Option<&mut ExplicitCongestionNotificationState>
	{
		self.explicit_congestion_notification_state.as_mut()
	}
	
	#[inline(always)]
	pub(crate) fn add_explicit_congestion_echo_flag_to_acknowledgment_if_appropriate(&self, flags: Flags) -> Flags
	{
		if let Some(ref explicit_congestion_notification_state) = self.explicit_congestion_notification_state
		{
			if explicit_congestion_notification_state.acknowledgments_should_explicit_congestion_echo()
			{
				return flags | Flags::ExplicitCongestionEcho
			}
		}
		flags
	}
	
	#[inline(always)]
	pub(crate) fn explicit_congestion_notification_reduced_congestion_window(&mut self)
	{
		if let Some(explicit_congestion_notification_state) = self.explicit_congestion_notification_state()
		{
			explicit_congestion_notification_state.reduced_congestion_window()
		}
	}
}

/// User time out.
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	#[inline(always)]
	pub(crate) fn schedule_user_time_out_alarm_for_connection(&mut self, alarms: &Alarms<TCBA>, connection_time_out: MillisecondDuration)
	{
		debug_assert!(self.is_state_synchronize_sent(), "This is only valid to do in the SynchronizeSent state");
		
		self.user_time_out_alarm.schedule(alarms, TickDuration::milliseconds_to_ticks_rounded_up(connection_time_out))
	}
}

macro_rules! increment_retransmissions
{
	($self: ident, $interface: ident, $now: ident) =>
	{
		{
			match $self.increment_retransmissions()
			{
				None =>
				{
					$self.aborted($interface, $now);
					return None
				}
				
				Some(number_of_transmissions) => number_of_transmissions,
			}
		}
	}
}

/// Retransmission and Zero-Window Probing.
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	#[inline(always)]
	fn cancel_retransmission_and_zero_window_probe_alarm(&mut self, alarms: &Alarms<TCBA>)
	{
		self.retransmission_and_zero_window_probe_alarm.cancel(alarms);
		self.retransmission_and_zero_window_probe_alarm_behaviour_mutable_reference().reset_retransmissions();
	}
	
	#[inline(always)]
	fn send_window_is_non_zero(&self) -> bool
	{
		!self.send_window_is_zero()
	}
	
	#[inline(always)]
	pub(crate) fn schedule_or_cancel_retransmission_and_zero_window_probe_alarm_as_appropriate(&mut self, alarms: &Alarms<TCBA>)
	{
		if self.retransmission_and_zero_window_probe_alarm.is_scheduled() && self.all_data_acknowledged() && self.send_window_is_non_zero()
		{
			self.cancel_retransmission_and_zero_window_probe_alarm(alarms);
		}
		else
		{
			if self.retransmission_and_zero_window_probe_alarm.is_cancelled()
			{
				self.retransmission_and_zero_window_probe_alarm_behaviour_mutable_reference().reset_retransmissions();
				self.retransmission_and_zero_window_probe_alarm.schedule(alarms, self.retransmission_time_out_tick_duration())
			}
		}
	}
	
	// Processing Incoming Segments 4.5.2.2: "... compute a new estimate of round-trip time.
	// If Snd.TS.OK bit is on, use Snd.TSclock - SEG.TSecr; otherwise, use the elapsed time since the first segment in the retransmission queue was sent".
	#[inline(always)]
	pub(crate) fn compute_a_new_estimate_of_round_trip_time_for_a_fully_acknowledged_segment(&mut self, now: MonotonicMillisecondTimestamp, fully_acknowledged_segment_timestamp: MonotonicMillisecondTimestamp, timestamps_option: Option<&TimestampsOption>)
	{
		if let Some(timestamping) = self.timestamping_reference()
		{
			// Missing a timestamps option (RFC 7323) is strictly only valid for Reset segments (eg ResetAcknowledgment).
			// There is also as of writing a check that timestamps are always present, but it may be relaxed for some non-compliant TCP stacks.
			if let Some(timestamps_option) = timestamps_option
			{
				// RFC 7323, Section 4.1: "The difference between a received TSecr value and the current timestamp clock value provides an RTT measurement".
				if let Some(measurement_of_round_trip_time) = timestamping.measurement_of_round_trip_time(now, timestamps_option.TSecr)
				{
					self.retransmission_and_zero_window_probe_alarm_behaviour_mutable_reference().process_measurement_of_round_trip_time(measurement_of_round_trip_time);
					return
				}
			}
		}
		
		self.retransmission_and_zero_window_probe_alarm_behaviour_mutable_reference().adjust_retransmission_time_out_based_on_acknowledgments(now, fully_acknowledged_segment_timestamp)
	}
	
	#[inline(always)]
	pub(crate) fn has_data_unacknowledged(&self) -> bool
	{
		!self.all_data_acknowledged()
	}
	
	#[inline(always)]
	pub(crate) fn all_data_acknowledged(&self) -> bool
	{
		self.SND.all_data_acknowledged()
	}
	
	#[inline(always)]
	pub(crate) fn send_window_is_zero(&self) -> bool
	{
		self.SND.window_is_zero()
	}
	
	#[inline(always)]
	pub(crate) fn retransmit_zero_window_probe(&mut self, interface: &Interface<TCBA>, now: Tick) -> Option<TickDuration>
	{
		debug_assert!(self.all_data_acknowledged());
		debug_assert!(self.send_window_is_zero());
		
		let time_that_has_elapsed_since_send_window_last_updated = self.SND.time_that_has_elapsed_since_send_window_last_updated(now);
		if interface.maximum_zero_window_probe_time_exceeded(time_that_has_elapsed_since_send_window_last_updated)
		{
			self.aborted(interface, now);
			return None
		}
		
		increment_retransmissions!(self, interface, now);
		
		if unlikely!(self.send_zero_window_probe_returning_true_if_failed(interface, now, false))
		{
			return None
		}
		
		// RFC 6298 Section 5: "(5.1) Every time a packet containing data is sent (including a retransmission), if the timer is not running, start it running so that it will expire after RTO seconds (for the current value of RTO)
		self.next_retransmission_or_zero_probe_alarm()
	}
	
	#[inline(always)]
	pub(crate) fn retransmit_data(&mut self, interface: &Interface<TCBA>, now: Tick) -> Option<TickDuration>
	{
		let now = now.to_milliseconds();
		
		let number_of_transmissions = increment_retransmissions!(self, interface, now);
		
		xxxx;
		let segment_sent_but_unacknowledged = transmission_control_block.segment_to_retransmit();
		
		// Congestion Control and Explicit Congestion Notification.
		{
			self.reset_congestion_window_to_loss_window_because_retransmission_timed_out();
			
			let is_first_retransmission = number_of_transmissions == 1;
			if is_first_retransmission
			{
				segment_sent_but_unacknowledged.clear_explicit_congestion_notifications_when_retransmitting();
				
				transmission_control_block.rfc_5681_section_7_paragaph_6_set_ssthresh_to_half_of_flight_size_on_first_retransmission();
			}
		}
		
		// RFC 6298 Section 5: "(5.4) Retransmit the earliest segment that has not been acknowledged by the TCP receiver".
		// TODO: Retransmit unack'd packet - involves incrementing refcnt.
		
		// TODO: Do we need to reset the timestamp option? Yes.
		
		xxxx;
		
		// RFC 6298 Section 5: "(5.1) Every time a packet containing data is sent (including a retransmission), if the timer is not running, start it running so that it will expire after RTO seconds (for the current value of RTO)
		self.next_retransmission_or_zero_probe_alarm()
	}
	
	#[inline(always)]
	pub(crate) fn smoothed_round_trip_time_and_round_trip_time_variance(&self) -> (MillisecondDuration, MillisecondDuration)
	{
		self.retransmission_and_zero_window_probe_alarm_behaviour_reference().smoothed_round_trip_time_and_round_trip_time_variance()
	}
	
	#[inline(always)]
	fn send_zero_window_probe_returning_true_if_failed(&mut self, interface: &Interface<TCBA>, now: MonotonicMillisecondTimestamp, is_transmission_not_retransmission: bool) -> bool
	{
		if unlikely!(interface.send_zero_window_probe(self, now).is_err())
		{
			self.aborted(interface, now);
			true
		}
		else
		{
			if is_transmission_not_retransmission
			{
				self.congestion_control.last_sent_data_at = now;
			}
			false
		}
	}
	
	#[inline(always)]
	fn retransmission_time_out_entering_established_state(&mut self)
	{
		self.retransmission_and_zero_window_probe_alarm_behaviour_mutable_reference().entering_established_state()
	}
	
	#[inline(always)]
	fn next_retransmission_or_zero_probe_alarm(&self) -> Option<TickDuration>
	{
		Some(self.retransmission_time_out_tick_duration())
	}
	
	#[inline(always)]
	fn increment_retransmissions(&mut self) -> Option<u8>
	{
		self.retransmission_and_zero_window_probe_alarm_behaviour_mutable_reference().increment_retransmissions()
	}
	
	#[inline(always)]
	fn retransmission_time_out_tick_duration(&self) -> TickDuration
	{
		TickDuration::milliseconds_to_ticks_rounded_up(self.retransmission_time_out())
	}
	
	/// RFC 6298 Section 5: "(5.6) Start the retransmission timer, such that it expires after RTO seconds (for the value of RTO after the doubling operation outlined in 5.5)".
	#[inline(always)]
	fn retransmission_time_out(&self) -> MillisecondDuration
	{
		self.retransmission_and_zero_window_probe_alarm_behaviour_reference().retransmission_time_out()
	}
	
	#[inline(always)]
	fn retransmission_and_zero_window_probe_alarm_behaviour_reference(&self) -> &mut RetransmissionAndZeroWindowProbeAlarmBehaviour
	{
		self.retransmission_and_zero_window_probe_alarm.alarm_behaviour_reference()
	}
	
	#[inline(always)]
	fn retransmission_and_zero_window_probe_alarm_behaviour_mutable_reference(&mut self) -> &mut RetransmissionAndZeroWindowProbeAlarmBehaviour
	{
		self.retransmission_and_zero_window_probe_alarm.alarm_behaviour_mutable_reference()
	}
}

/// Timestamps and timestamping.
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	// RFC 7323, Section 3.2, Pages 12-13:-
	// "Once TSopt has been successfully negotiated, that is both <SYN> and <SYN,ACK> contain TSopt, the TSopt MUST be sent in every non-<RST> segment for the duration of the connection, and SHOULD be sent in an <RST> segment.
	// ...
	// If a non-<RST> segment is received without a TSopt, a TCP SHOULD silently drop the segment".
	#[inline(always)]
	pub(crate) fn timestamps_are_required_in_all_segments_except_reset(&self) -> bool
	{
		debug_assert!(self.is_state_synchronized(), "This method is only valid once state is synchronized");
		
		self.timestamping.is_some()
	}
	
	#[inline(always)]
	pub(crate) fn update_Last_ACK_sent(&mut self, ACK: WrappingSequenceNumber)
	{
		if let Some(timestamping) = self.timestamping_mutable_reference()
		{
			timestamping.unwrap().update_Last_ACK_sent(ACK);
		}
	}
	
	#[inline(always)]
	pub(crate) fn normal_timestamps_option(&self) -> TimestampsOption
	{
		debug_assert_eq!(self.state, State::SynchronizeSent, "Only valid for SynchronizeSent");
		
		self.timestamping_reference_unwrapped().normal_timestamps_option()
	}
	
	#[inline(always)]
	pub(crate) fn timestamping_reference(&self) -> Option<&Timestamping>
	{
		self.timestamping.as_ref()
	}
	
	#[inline(always)]
	pub(crate) fn enable_timestamping(&mut self, timestamps_option: TimestampsOption)
	{
		self.timestamping_mutable_reference_unwrapped().set_TS_Recent(timestamps_option.TSval)
	}
	
	#[inline(always)]
	pub(crate) fn disable_timestamping(&mut self)
	{
		self.timestamping = None
	}
	
	#[inline(always)]
	fn timestamping_mutable_reference_unwrapped(&self) -> &mut Timestamping
	{
		self.timestamping_mutable_reference().unwrap()
	}
	
	#[inline(always)]
	pub(crate) fn timestamping_mutable_reference(&self) -> Option<&mut Timestamping>
	{
		self.timestamping.as_mut()
	}
	
	#[inline(always)]
	fn timestamping_reference_unwrapped(&self) -> &Timestamping
	{
		self.timestamping_reference().unwrap()
	}
}

/// Authentication.
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	#[inline(always)]
	pub(crate) fn md5_authentication_key(&self) -> Option<&Rc<Md5PreSharedSecretKey>>
	{
		self.md5_authentication_key.as_ref()
	}
	
	#[inline(always)]
	pub(crate) fn authentication_is_required(&self) -> bool
	{
		self.md5_authentication_key.is_some()
	}
}

/// State information.
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	#[inline(always)]
	pub(crate) fn is_state_established(&self) -> bool
	{
		self.state().is_established()
	}
	
	#[inline(always)]
	pub(crate) fn is_state_synchronize_sent(&self) -> bool
	{
		self.state().is_synchronize_sent()
	}
	
	#[inline(always)]
	pub(crate) fn is_state_synchronized(&self) -> bool
	{
		self.state().is_synchronized()
	}
	
	#[inline(always)]
	pub(crate) fn state(&self) -> State
	{
		self.state.get()
	}
	
	#[inline(always)]
	pub(crate) fn enter_state_established(&mut self)
	{
		self.retransmission_time_out_entering_established_state();
		self.set_state(State::Established);
		self.events_receiver.entered_state_established();
	}
	
	// set_state(State::Established)
	// enter_state_established
	#[inline(always)]
	fn set_state(&mut self, state: State)
	{
		debug_assert!(state > self.state(), "new state '{:?}' does not advance from existing state '{:?}", state, self.state());
		
		self.state.set(state)
	}
}
