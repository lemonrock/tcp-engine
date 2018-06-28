// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Identifies connections for which MD5 signatures for TCP segments must be present on an interface.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Md5AuthenticationConnectionIdentifier<Address: InternetProtocolAddress>
{
	remote_internet_protocol_address: Address,
	local_port: NetworkEndianU16,
}

impl<Address: InternetProtocolAddress> Md5AuthenticationConnectionIdentifier<Address>
{
	/// Create a new instance.
	#[inline(always)]
	pub const fn new(remote_internet_protocol_address: Address, local_port: NetworkEndianU16) -> Self
	{
		Self
		{
			remote_internet_protocol_address,
			local_port,
		}
	}
}
