// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Actions to take for an incoming segment.
pub trait IncomingSegmentAction<TCBA: TransmissionControlBlockAbstractions, I: NetworkDeviceInterface<TCBA>>
{
	/// New instance.
	#[inline(always)]
	fn new<'a, 'b>(now: MonotonicMillisecondTimestamp, packet: TCBA::Packet, interface: &'a I, source_internet_protocol_address: &'b TCBA::Address, SEG: &'b TcpSegment, tcp_options: TcpOptions, options_length: usize, tcp_segment_length: usize) -> Self;
	
	#[allow(missing_docs)]
	#[inline(always)]
	fn received_synchronize_when_state_is_listen_or_synchronize_received(&mut self, md5_authentication_key: Option<Rc<Md5PreSharedSecretKey>>, explicit_congestion_notification_supported: bool);
	
	#[allow(missing_docs)]
	#[inline(always)]
	fn received_acknowledgment_when_state_is_listen_or_synchronize_received(&mut self, md5_authentication_key: Option<Rc<Md5PreSharedSecretKey>>);
	
	#[allow(missing_docs)]
	#[inline(always)]
	fn process_tcp_segment_when_state_is_other_than_listen_or_synchronize_received(&mut self, transmission_control_block: &mut I::TCB);
}
