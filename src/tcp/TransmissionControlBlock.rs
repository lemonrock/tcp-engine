// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A Transmission Control Block (TCB) which is the 'the data structure that records the state of a connection' (RFC 793, Glossary, Page 84).
#[derive(Debug)]
pub(crate) struct TransmissionControlBlock<TCBA: TransmissionControlBlockAbstractions>
{
	/// This duplicates information already held in the HashMap of transmission_control_blocks in Interface.
	///
	/// It is here also as this data is needed when removing a transmission_control_block from an alarm (eg linger); when removing in other circumstances, the information is available from the incoming SEG.
	key: TransmissionControlBlockKey<TCBA::Address>,
	
	state: State,
	RCV: TransmissionControlBlockReceive,
	SND: TransmissionControlBlockSend,
	
	unacknowledged_sent_segments: UnacknowledgedSegments,
	
	events_receiver: <<TCBA as TransmissionControlBlockAbstractions>::EventsReceiverCreator as TransmissionControlBlockEventsReceiverCreator>::EventsReceiver,
	
	retransmission_time_out_alarm: Alarm<RetransmissionTimeOutAlarmBehaviour<TCBA>, TCBA>,
	keep_alive_alarm: Alarm<KeepAliveAlarmBehaviour<TCBA>, TCBA>,
	linger_alarm: Alarm<LingerAlarmBehaviour<TCBA>, TCBA>,
	
	timestamping: Option<Timestamping>,
	
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
	///
	/// This value is uninitialized until the state becomes established.
	maximum_segment_size_to_send_to_remote: u16,
	
	/// This value is uninitialized until the state becomes established.
	selective_acknowledgments_permitted: bool,
}

impl<TCBA: TransmissionControlBlockAbstractions> TransmissionControlBlock<TCBA>
{
	/// RFC 793, Page 54, OPEN Call: "A SYN segment of the form <SEQ=ISS><CTL=SYN> is sent. Set SND.UNA to ISS, SND.NXT to ISS+1, enter SYN-SENT state, and return".
	///
	/// This variant of open does not send any data.
	#[inline(always)]
	pub(crate) fn new_for_open(interface: &Interface<TCBA>, remote_internet_protocol_address: TCBA::Address, remote_port_local_port: RemotePortLocalPort) -> Self
	{
		let ISS = interface.generate_initial_sequence_number(remote_internet_protocol_address, remote_port_local_port);
		
		let key = TransmissionControlBlockKey::for_client(remote_internet_protocol_address, for_client);
		
		let RCV_NXT = WrappingSequenceNumber::Zero;
		
		Self
		{
			events_receiver: TCBA::EventReceiverCreator::create(&key),
			
			key,
		
			state: Cell::new(State::SynchronizeSent),
			
			RCV: RefCell::new
			(
				TransmissionControlBlockReceive
				{
					NXT: RCV_NXT,
					WND: InitialWindowSize::TrueWindow,
					Wind: Wind
					{
						Scale: InitialWindowSize::Scale
					},
					processed: RCV_NXT,
				}
			),
			
			SND: RefCell::new
			(
				TransmissionControlBlockSend
				{
					UNA: ISS,
					NXT: ISS + 1,
					WND: WindowSize::Zero,
					Wind: Wind
					{
						Scale: WindowScaleOption::Zero,
					},
					WL1: WrappingSequenceNumber::Zero,
					WL2: WrappingSequenceNumber::Zero,
				}
			),
			
			unacknowledged_sent_segments: UnacknowledgedSegments::default(),
			
			retransmission_time_out_alarm: Default::default(),
			keep_alive_alarm: Default::default(),
			linger_alarm: Default::default(),
			
			timestamping: Timestamping::new_for_client_opener(RCV_NXT),
			
			we_are_the_listener: false,
			
			maximum_segment_size_to_send_to_remote: 0,
			selective_acknowledgments_permitted: false,
		}
	}
	
	#[inline(always)]
	pub(crate) fn new_for_listen(interface: &Interface<TCBA>, source_internet_protocol_address: &TCBA::Address, SEG: &ParsedTcpSegment, tcp_options: &TcpOptions, now: MonotonicMillisecondTimestamp) -> Self
	{
		let remote_internet_protocol_address = source_internet_protocol_address;
		let key = TransmissionControlBlockKey::from_incoming_segment(remote_internet_protocol_address, SEG);
		
		let unscaled_receive_window = InitialWindowSize::Segment;
		let unscaled_send_window = SEG.WND;
		
		let (receive_window, receive_window_scale, send_window, send_window_scale) = match parsed_syncookie.their_window_scale
		{
			None => (unscaled_receive_window, WindowScaleOption::EquivalentToNoWindowScale, unscaled_send_window, WindowScaleOption::EquivalentToNoWindowScale),
			
			Some(send_window_scale) =>
			{
				let receive_window_scale = interface.window_scale;
				(unscaled_receive_window << receive_window_scale, receive_window_scale, unscaled_send_window << send_window_scale, send_window_scale)
			}
		};
		
		let RCV_NXT = SEG.SEQ;
		
		Self
		{
			events_receiver: TCBA::EventReceiverCreator::create(&key),
			
			key,
			
			state: Cell::new(State::Established),
			
			RCV: RefCell::new
			(
				TransmissionControlBlockReceive
				{
					NXT: RCV_NXT,
					WND: receive_window,
					Wind: Wind
					{
						Scale: receive_window_scale
					},
					processed: RCV_NXT,
				}
			),
			
			SND: RefCell::new
			(
				TransmissionControlBlockSend
				{
					UNA: parsed_syncookie.ISS,
					NXT: SEG.ACK,
					WND: send_window,
					Wind: Wind
					{
						Scale: send_window_scale,
					},
					WL1: SEG.SEQ,
					WL2: SEG.ACK,
				}
			),
			
			unacknowledged_sent_segments: UnacknowledgedSegments::default(),
			
			retransmission_time_out_alarm: Default::default(),
			keep_alive_alarm: Default::default(),
			linger_alarm: Default::default(),
			
			timestamping: Timestamping::new_for_server_listener(tcp_options, now, RCV_NXT),
			
			we_are_the_listener: true,
			
			maximum_segment_size_to_send_to_remote: min(parsed_syncookie.their_maximum_segment_size, interface.our_current_maximum_segment_size_without_fragmentation(remote_internet_protocol_address)),
			selective_acknowledgments_permitted: parsed_syncookie.their_selective_acknowledgment_permitted,
		}
	}
	
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
	pub(crate) fn record_last_acknowledgment_occurred_at(&mut self, now: MonotonicMillisecondTimestamp)
	{
		self.keep_alive_alarm.record_last_acknowledgment_occurred_at(now);
	}
	
	#[inline(always)]
	pub(crate) fn begin_time_wait(&mut self, interface: &Interface<TCBA>)
	{
		interface.send_acknowledgment(transmission_control_block);
		
		self.set_state(State::TimeWait);
		self.events_receiver.begin_time_wait();
		
		let alarms = interface.alarms();
		self.retransmission_time_out_alarm.cancel(alarms);
		self.keep_alive_alarm.cancel(alarms);
		self.linger_alarm.schedule(alarms, alarms.linger_time)
	}
	
	#[inline(always)]
	pub(crate) fn close(&mut self, interface: &Interface<TCBA>)
	{
		self.events_receiver.finish();
		//self.set_state(State::Closed);
		self.cancel_alarms(interface);
		self.unacknowledged_sent_segments.remove_all();
		interface.remove_transmission_control_block(&self.key)
	}
	
	#[inline(always)]
	pub(crate) fn forcibly_close(&mut self, interface: &Interface<TCBA>)
	{
		self.events_receiver.finish_forcibly_closed(self.is_state_established());
		//self.set_state(State::Closed);
		self.cancel_alarms(interface);
		self.unacknowledged_sent_segments.remove_all();
		interface.remove_transmission_control_block(&self.key)
	}
	
	#[inline(always)]
	pub(crate) fn error_connection_reset(&mut self, interface: &Interface<TCBA>)
	{
		self.events_receiver.finish_forcibly_closed(false);
		//self.set_state(State::Closed);
		self.cancel_alarms(interface);
		self.unacknowledged_sent_segments.remove_all();
		interface.remove_transmission_control_block(&self.key)
	}
	
	#[inline(always)]
	fn cancel_alarms(&mut self, interface: &Interface<TCBA>)
	{
		let alarms = interface.alarms();
		self.retransmission_time_out_alarm.cancel(alarms);
		self.keep_alive_alarm.cancel(alarms);
		self.linger_alarm.cancel(alarms);
	}
	
	#[inline(always)]
	pub(crate) fn remove_all_sent_segments_up_to(&mut self, up_to_sequence_number: WrappingSequenceNumber) -> Option<MonotonicMillisecondTimestamp>
	{
		self.unacknowledged_sent_segments.remove_all_from_first_up_to(up_to_sequence_number)
	}
	
	// RFC 7323, Section 4.1: "The difference between a received TSecr value and the current timestamp clock value provides an RTT measurement".
	#[inline(always)]
	pub(crate) fn adjust_retransmission_time_out_based_on_timestamps(&mut self, now: MonotonicMillisecondTimestamp, timestamps_option: TimestampOption)
	{
		let measurement_of_round_trip_time = self.timestamping_mutable_reference().unwrap().measurement_of_round_trip_time(now, timestamps_option.TSecr);
		
		if let Some(measurement_of_round_trip_time) = measurement_of_round_trip_time
		{
			self.retransmission_time_out_alarm.alarm_behaviour.process_measurement_of_round_trip_time(measurement_of_round_trip_time)
		}
	}
	
	#[inline(always)]
	pub(crate) fn adjust_retransmission_time_out_based_on_acknowledgments(&mut self, now: MonotonicMillisecondTimestamp, timestamp: MonotonicMillisecondTimestamp)
	{
		self.retransmission_time_out_alarm.alarm_behaviour.adjust_retransmission_time_out_based_on_acknowledgments(now, timestamp)
	}
	
	// RFC 7323, Section 3.2, Pages 12-13:-
	// "Once TSopt has been successfully negotiated, that is both <SYN> and <SYN,ACK> contain TSopt, the TSopt MUST be sent in every non-<RST>segment for the duration of the connection, and SHOULD be sent in an <RST> segment."
	// "If a non-<RST> segment is received without a TSopt, a TCP SHOULD silently drop the segment."
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
	pub(crate) fn subsequent_timestamps_option(&self) -> TimestampsOption
	{
		self.timestamping_reference().subsequent_timestamps_option()
	}
	
	#[inline(always)]
	pub(crate) fn we_are_the_listener(&self) -> bool
	{
		self.we_are_the_listener
	}
	
	#[inline(always)]
	pub(crate) fn is_state_not_time_wait(&self) -> bool
	{
		self.state().is_not_time_wait()
	}
	
	#[inline(always)]
	pub(crate) fn is_state_established(&self) -> bool
	{
		self.state().is_established()
	}
	
	#[inline(always)]
	pub(crate) fn is_state_after_exchange_of_synchronized(&self) -> bool
	{
		self.state().is_after_exchange_of_synchronized()
	}
	
	#[inline(always)]
	pub(crate) fn is_state_before_closing_or_time_wait(&self) -> bool
	{
		self.state().is_before_closing_or_time_wait()
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
