// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Creates a transmission control block.
pub trait CreateTransmissionControlBlock<Address: InternetProtocolAddress>
{
	/// Creates a Transmission Control Block (TCB) suitable for an outbound client connection.
	#[inline(always)]
	fn new_for_closed_to_synchronize_sent(key: TransmissionControlBlockKey<Address>, now: MonotonicMillisecondTimestamp, maximum_segment_size_to_send_to_remote: u16, recent_connection_data: &RecentConnectionData, md5_authentication_key: Option<Rc<Md5PreSharedSecretKey>>, magic_ring_buffer: MagicRingBuffer, congestion_control: CongestionControl, ISS: WrappingSequenceNumber) -> Self;
	
	/// Creates a Transmission Control Block (TCB) suitable for an inbound server (listener) connection.
	#[inline(always)]
	fn new_for_sychronize_received_to_established(key: TransmissionControlBlockKey<Address>, now: MonotonicMillisecondTimestamp, maximum_segment_size_to_send_to_remote: u16, recent_connection_data: &RecentConnectionData, md5_authentication_key: Option<Rc<Md5PreSharedSecretKey>>, magic_ring_buffer: MagicRingBuffer, congestion_control: CongestionControl, SEG_WND: SegmentWindowSize, tcp_options: &TcpOptions, parsed_syncookie: ParsedSynCookie) -> Self;
	
	/// A key that identifies this connection; composed of the remote internet protocol address, remote port and local port.
	#[inline(always)]
	fn key(&self) -> &TransmissionControlBlockKey<Address>;
}
