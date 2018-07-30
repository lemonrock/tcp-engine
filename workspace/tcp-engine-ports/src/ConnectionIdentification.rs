// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Connection Identification.
pub trait ConnectionIdentification<Address: InternetProtocolAddress>
{
	/// Remote internet protocol address.
	#[inline(always)]
	fn remote_internet_protocol_address(&self) -> &Address;
	
	/// Remote port-local port combination.
	#[inline(always)]
	fn remote_port_local_port(&self) -> RemotePortLocalPort;
	
	/// Are we the listener (ie server, not an outbound client connection).
	#[inline(always)]
	fn we_are_the_listener(&self) -> bool;
	
	#[doc(hidden)]
	#[inline(always)]
	fn we_are_the_client(&self) -> bool
	{
		!self.we_are_the_listener()
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn debug_assert_we_are_the_client(&self)
	{
		debug_assert!(self.we_are_the_client(), "We are the listener (server)")
	}
}
