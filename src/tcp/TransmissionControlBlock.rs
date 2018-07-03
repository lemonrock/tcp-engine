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
	MAX: TransmissionControlBlockMaxima,
	
	segments_sent_but_unacknowledged: SegmentsSentButUnacknowledged,
	
	events_receiver: <<TCBA as TransmissionControlBlockAbstractions>::EventsReceiverCreator as TransmissionControlBlockEventsReceiverCreator>::EventsReceiver,
	
	retransmission_time_out_alarm: Alarm<RetransmissionTimeOutAlarmBehaviour<TCBA>, TCBA>,
	keep_alive_alarm: Alarm<KeepAliveAlarmBehaviour<TCBA>, TCBA>,
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
	/// RFC 879, Section 1: "The default TCP Maximum Segment Size is 536".
	///
	/// RFC 879, Section 3, Paragraph 2: "The MSS counts only data octets in the segment, it does not count the TCP header or the IP header".
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
		
		let RCV_NXT = WrappingSequenceNumber::Zero;
		let md5_authentication_key = interface.find_md5_authentication_key(remote_internet_protocol_address, remote_port_local_port).map(|key_reference| key_reference.clone());
		
		Self
		{
			events_receiver: TCBA::EventReceiverCreator::create(&key),
			
			key,
			
			state: State::SynchronizeSent,
			
			RCV: TransmissionControlBlockReceive
			{
				NXT: RCV_NXT,
				WND: InitialWindowSize::TrueWindow,
				Wind: Wind
				{
					Shift: InitialWindowSize::Shift
				},
			},
			
			SND: TransmissionControlBlockSend
			{
				UNA: ISS,
				NXT: ISS + 1,
				MAX: ISS + 1,
				WND: WindowSize::Zero,
				Wind: Wind
				{
					Shift: WindowScaleOption::Zero,
				},
				WL1: WrappingSequenceNumber::Zero,
				WL2: WrappingSequenceNumber::Zero,
			},
			
			MAX: TransmissionControlBlockMaxima
			{
				SND: TransmissionControlBlockMaxima
				{
					WND: WindowSize::Zero,
				}
			},
			
			segments_sent_but_unacknowledged: SegmentsSentButUnacknowledged::default(),
			
			retransmission_time_out_alarm: RetransmissionTimeOutAlarmBehaviour::new(&cached_congestion_data),
			keep_alive_alarm: Default::default(),
			user_time_out_alarm: Default::default(),
			
			timestamping: Timestamping::new_for_client_opener(RCV_NXT),
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
			
			congestion_control: CongestionControl::new(Self::InitialCongestionWindowAlgorithm, MonotonicMillisecondDuration::Zero, CongestionControl::calculate_sender_maximum_segment_size_in_non_synchronized_state(maximum_segment_size, true, md5_authentication_key.is_some(), true, true, true), &cached_congestion_data),
		}
	}
	
	#[inline(always)]
	pub(crate) fn new_for_sychronize_received_to_established(interface: &Interface<TCBA>, source_internet_protocol_address: &TCBA::Address, SEG: &ParsedTcpSegment, tcp_options: &TcpOptions, parsed_syncookie: ParsedSynCookie, now: MonotonicMillisecondTimestamp, md5_authentication_key: Option<Rc<Md5PreSharedSecretKey>>) -> Self
	{
		let remote_internet_protocol_address = source_internet_protocol_address;
		
		let cached_congestion_data = interface.cached_congestion_data(now, &remote_internet_protocol_address);
		
		let key = TransmissionControlBlockKey::from_incoming_segment(remote_internet_protocol_address, SEG);
		
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
		let SND_recover = ISS;
		let SND_UNA = ISS;
		
		let SND_WL1 = IRS;
		let SND_WL2 = ISS;
		let SND_NXT = ISS + 1;
		
		let RCV_ADV = RCV_NXT + RCV_WND;
		let maximum_segment_size = MaximumSegmentSizeOption::maximum_segment_size_to_send_to_remote_u16(parsed_syncookie.their_maximum_segment_size, interface, remote_internet_protocol_address);
		let selective_acknowledgments_permitted = parsed_syncookie.their_selective_acknowledgment_permitted;
		let timestamping = Timestamping::new_for_server_listener(tcp_options, now, RCV_NXT);
		
		Self
		{
			events_receiver: TCBA::EventReceiverCreator::create(&key),
			
			key,
			
			state: State::Established,
			
			RCV: TransmissionControlBlockReceive
			{
				NXT: RCV_NXT,
				WND: RCV_WND,
				Wind: Wind
				{
					Shift: RCV_Wind_Shift
				},
			},
			
			SND: TransmissionControlBlockSend
			{
				UNA: SND_UNA,
				NXT: SND_NXT,
				WND: SND_WND,
				Wind: Wind
				{
					Shift: SND_Wind_Shift,
				},
				WL1: SND_WL1,
				WL2: SND_WL2,
			},
			
			MAX: TransmissionControlBlockMaxima
			{
				SND: TransmissionControlBlockMaxima
				{
					WND: SND_WND,
				}
			},
			
			segments_sent_but_unacknowledged: SegmentsSentButUnacknowledged::default(),
			
			retransmission_time_out_alarm: RetransmissionTimeOutAlarmBehaviour::new(&cached_congestion_data),
			keep_alive_alarm: Default::default(),
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
			
			congestion_control: CongestionControl::new(Self::InitialCongestionWindowAlgorithm, now, CongestionControl::calculate_sender_maximum_segment_size_in_synchronized_state(maximum_segment_size, timestamping.is_some(), md5_authentication_key.is_some(), selective_acknowledgments_permitted), &cached_congestion_data),
		}
	}
	
	#[inline(always)]
	pub(crate) fn our_offered_maximum_segment_size_when_initiating_connections(&self) -> MaximumSegmentSizeOption
	{
		debug_assert!(!self.we_are_the_listener, "We are the listener (server)");
		
		MaximumSegmentSizeOption::from(self.maximum_segment_size_to_send_to_remote)
	}
	
	#[inline(always)]
	pub(crate) fn SEND(&mut self, interface: &Interface<TCBA>)
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
			
			SynchronizeReceived => unreachable_synthetic_state!("TCP state SynchronizeReceived is replaced with SYN flood defences 'process_for_acknowledgment_of_syncookie'"),
			
			Established | CloseWait =>
			{
				// TODO: Segmentize, send with piggbacked ack if possible
			}
			
			FinishWait1 | FinishWait2 | Closing | LastAcknowledgment | TimeWait =>
			{
				// TODO: Error connection closing
			}
		}
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
			
			SynchronizeSent => self.close(interface, now),
			
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
			
			SynchronizeSent => self.forcibly_close(interface),
			
			SynchronizeReceived => unreachable_synthetic_state!("TCP state SynchronizeReceived is replaced with SYN flood defences 'process_for_acknowledgment_of_syncookie'"),
			
			Established | FinishWait1 | FinishWait2 | CloseWait =>
			{
				interface.send_reset_without_packet_to_reuse(self, now, transmission_control_block.SND.NXT);
				self.forcibly_close(interface)
			}
			
			Closing | LastAcknowledgment => self.forcibly_close(interface),
			
			TimeWait => self.close(interface, now.to_milliseconds()),
		}
		
		None
	}
	
	#[inline(always)]
	fn cancel_alarms(&mut self, interface: &Interface<TCBA>)
	{
		let alarms = interface.alarms();
		self.retransmission_time_out_alarm.cancel(alarms);
		self.keep_alive_alarm.cancel(alarms);
		self.user_time_out_alarm.cancel(alarms);
	}
	
	#[inline(always)]
	pub(crate) fn close(&mut self, interface: &Interface<TCBA>, now: MonotonicMillisecondTimestamp)
	{
		self.events_receiver.finish();
		//self.set_state(State::Closed);
		self.cancel_alarms(interface);
		self.segments_sent_but_unacknowledged.remove_all();
		
		interface.update_recent_congestion_data(self, now);
		
		interface.remove_transmission_control_block(&self.key)
	}
	
	#[inline(always)]
	pub(crate) fn forcibly_close(&mut self, interface: &Interface<TCBA>)
	{
		self.events_receiver.finish_forcibly_closed(self.is_state_established());
		//self.set_state(State::Closed);
		self.cancel_alarms(interface);
		self.segments_sent_but_unacknowledged.remove_all();
		
		interface.remove_transmission_control_block(&self.key)
	}
	
	#[inline(always)]
	pub(crate) fn error_connection_reset(&mut self, interface: &Interface<TCBA>)
	{
		self.events_receiver.finish_forcibly_closed(false);
		//self.set_state(State::Closed);
		self.cancel_alarms(interface);
		self.segments_sent_but_unacknowledged.remove_all();
		
		interface.remove_transmission_control_block(&self.key)
	}
	
	#[inline(always)]
	pub(crate) fn connection_reset_established_fin_wait_1_fin_wait_2_close_wait(&mut self, interface: &Interface<TCBA>)
	{
		// See Processing Incoming Segments 4.2.2.1
		self.events_receiver.finish_forcibly_closed(true);
		//self.set_state(State::Closed);
		self.cancel_alarms(interface);
		self.segments_sent_but_unacknowledged.remove_all();
		
		interface.remove_transmission_control_block(&self.key)
	}
	
	#[inline(always)]
	pub(crate) fn connection_reset_closing_last_acknowledgment_time_wait(&mut self, interface: &Interface<TCBA>)
	{
		// See Processing Incoming Segments 4.2.2.1
		self.events_receiver.finish_forcibly_closed(true);
		//self.set_state(State::Closed);
		self.cancel_alarms(interface);
		self.segments_sent_but_unacknowledged.remove_all();
		
		interface.remove_transmission_control_block(&self.key)
	}
}

/// Congestion Control.
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	const InitialCongestionWindowAlgorithm: InitialCongestionWindowAlgorithm = InitialCongestionWindowAlgorithm::RFC_6928;
	
	#[inline(always)]
	pub(crate) fn record_last_acknowledgment_which_moved_SND_UNA(&mut self, now: MonotonicMillisecondTimestamp)
	{
		self.keep_alive_alarm.record_last_acknowledgment_occurred_at(now);
		
		self.congestion_control.record_last_acknowledgment_occurred_at(now);
		
		// RFC 5681 Section 5.2 Paragraph 2 implies acknowledgments which DO move SND.UNA reset the duplicate acknowledgments count.
		self.congestion_control.reset_duplicate_acknowledgment_count();
	}
	
	#[inline(always)]
	pub(crate) fn increase_bytes_acknowledged(&mut self, by_amount_of_bytes: u32)
	{
		self.congestion_control.increase_bytes_acknowledged(by_amount_of_bytes)
	}
	
	#[inline(always)]
	pub(crate) fn has_outstanding_data(&self) -> bool
	{
		self.segments_sent_but_unacknowledged.is_not_empty()
	}
	
	#[inline(always)]
	pub(crate) fn increment_duplicate_acknowledgments_received_without_any_intervening_acknwoledgments_which_moved_SND_UNA(&mut self)
	{
		self.congestion_control.increment_duplicate_acknowledgments_received_without_any_intervening_acknwoledgments_which_moved_SND_UNA()
	}
	
	#[inline(always)]
	pub(crate) fn recalculate_sender_maximum_segment_size_when_entering_established_state(&mut self)
	{
		self.congestion_control.recalculate_sender_maximum_segment_size_when_entering_established_state(self.maximum_segment_size_to_send_to_remote, self.timestamping.is_some(), self.md5_authentication_key.is_some(), self.selective_acknowledgments_permitted)
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
	pub(crate) fn maximum_payload_size_excluding_synchronize_and_finish(&mut self, now: MonotonicMillisecondTimestamp, padded_options_size: usize) -> u32
	{
		let maximum_data = self.maximum_data(now);
		let maximum_segment_payload_size = self.maximum_segment_size_to_send_to_remote - ((size_of::<TcpFixedHeader>() + padded_options_size) as u32);
		min(maximum_segment_payload_size, min(maximum_data, self.SND.WND.into()))
	}
	
	#[inline(always)]
	fn maximum_data(&mut self, now: MonotonicMillisecondTimestamp) -> u32
	{
		self.congestion_control.reset_congestion_window_to_restart_window_if_no_data_sent_for_an_interval_exceeding_the_retransmission_time_out(now, self.explicit_congestion_notification_state(), self.retransmission_time_out());
		
		self.congestion_control.maximum_data(&self.SND)
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

/// Retransmission.
impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	#[inline(always)]
	pub(crate) fn schedule_retransmission_time_out_alarm(&mut self, alarms: &Alarms<TCBA>)
	{
		self.retransmission_time_out_alarm.schedule(alarms, self.retransmission_time_out());
	}
	
	#[inline(always)]
	pub(crate) fn remove_all_sent_segments_up_to(&mut self, up_to_sequence_number: WrappingSequenceNumber) -> Option<MonotonicMillisecondTimestamp>
	{
		self.segments_sent_but_unacknowledged.remove_all_from_first_up_to(up_to_sequence_number)
	}
	
	// RFC 7323, Section 4.1: "The difference between a received TSecr value and the current timestamp clock value provides an RTT measurement".
	#[inline(always)]
	pub(crate) fn adjust_retransmission_time_out_based_on_timestamps(&mut self, now: MonotonicMillisecondTimestamp, timestamps_option: TimestampOption)
	{
		let measurement_of_round_trip_time = self.timestamping_mutable_reference().unwrap().measurement_of_round_trip_time(now, timestamps_option.TSecr);
		
		if let Some(measurement_of_round_trip_time) = measurement_of_round_trip_time
		{
			self.retransmission_time_out_alarm_behaviour_mutable_reference().process_measurement_of_round_trip_time(measurement_of_round_trip_time)
		}
	}
	
	#[inline(always)]
	pub(crate) fn adjust_retransmission_time_out_based_on_acknowledgments(&mut self, now: MonotonicMillisecondTimestamp, timestamp: MonotonicMillisecondTimestamp)
	{
		self.retransmission_time_out_alarm_behaviour_mutable_reference().adjust_retransmission_time_out_based_on_acknowledgments(now, timestamp)
	}
	
	#[inline(always)]
	fn retransmission_time_out(&self) -> MillisecondDuration
	{
		self.retransmission_time_out_alarm.retransmission_time_out.retransmission_time_out
	}
	
	#[inline(always)]
	fn next_unacknowledged_segment(&mut self) -> &mut SegmentSentButUnacknowledged<TCBA>
	{
		self.segments_sent_but_unacknowledged.next_unacknowledged_segment()
	}
	
	#[inline(always)]
	fn retransmission_time_out_alarm_behaviour_mutable_reference(&mut self)
	{
		self.retransmission_time_out_alarm.alarm_behaviour_mutable_reference()
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
	pub(crate) fn timestamping_reference(&self) -> Option<&Timestamping>
	{
		self.timestamping.as_ref()
	}
	
	#[inline(always)]
	pub(crate) fn timestamping_mutable_reference(&self) -> Option<&mut Timestamping>
	{
		self.timestamping.as_mut()
	}
	
	#[inline(always)]
	pub(crate) fn normal_timestamps_option(&self) -> TimestampsOption
	{
		self.timestamping_reference().normal_timestamps_option()
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
	pub(crate) fn set_state(&self, state: State)
	{
		debug_assert!(state > self.state(), "new state '{:?}' does not advance from existing state '{:?}", state, self.state());
		
		self.state.set(state)
	}
}
