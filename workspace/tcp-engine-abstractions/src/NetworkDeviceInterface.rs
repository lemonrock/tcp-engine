// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A network device interface.
pub trait NetworkDeviceInterface<TCBA: TransmissionControlBlockAbstractions>
{
	/// Type of transmission control block (TCB).
	type TCB: CreateTransmissionControlBlock<TCBA::Address> + ConnectionIdentification<TCBA::Address> + RecentConnectionDataProvider<TCBA::Address>;
	
	/// Are the transmission control blocks at maximum capacity?
	#[inline(always)]
	fn transmission_control_blocks_at_maximum_capacity(&self) -> bool;
	
	/// Find a transmission control block (TCB) for an incoming segment.
	#[inline(always)]
	fn find_transmission_control_block_for_incoming_segment(&self, remote_internet_protocol_address: &TCBA::Address, SEG: &TcpSegment) -> Option<&mut Self::TCB>;
	
	/// Find a MD5 authentication key.
	#[inline(always)]
	fn find_md5_authentication_key(&self, remote_internet_protocol_address: &TCBA::Address, local_port: NetworkEndianU16) -> Option<Rc<Md5PreSharedSecretKey>>;
	
	/// The network address of this interface.
	#[inline(always)]
	fn local_internet_protocol_address(&self) -> &TCBA::Address;
	
	/// Port combinations.
	#[inline(always)]
	fn listening_server_port_combination_validity(&self) -> &PortCombinationValidity;
}
