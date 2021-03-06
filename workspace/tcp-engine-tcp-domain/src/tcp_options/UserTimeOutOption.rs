// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// User Time Out Option.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(C, packed)]
pub struct UserTimeOutOption(NetworkEndianU32);

impl From<NetworkEndianU32> for UserTimeOutOption
{
	#[inline(always)]
	fn from(value: NetworkEndianU32) -> Self
	{
		UserTimeOutOption(value)
	}
}

impl Into<NetworkEndianU32> for UserTimeOutOption
{
	#[inline(always)]
	fn into(self) -> NetworkEndianU32
	{
		self.0
	}
}

impl UserTimeOutOption
{
	#[doc(hidden)]
	pub const Kind: u8 = 28;
	
	#[doc(hidden)]
	pub const KnownLength: usize = 4;
	
	/// See Section 13.3.5 of TCP/IP Illustrated, Volume 1 for this calculation.
	///
	/// `local_system_lower_time_out_limit` must be greater than the retransmission timout.
	#[inline(always)]
	pub fn user_timeout_seconds(self, local_system_lower_time_out_limit: u64, local_system_upper_time_out_limit: u64, our_advertised_user_time_out: u64) -> u64
	{
		min(local_system_upper_time_out_limit, max(max(our_advertised_user_time_out, self.to_advised_user_time_out_seconds()), local_system_lower_time_out_limit))
	}
	
	/// Converts.
	#[inline(always)]
	pub fn to_advised_user_time_out_seconds(self) -> u64
	{
		let native = self.0.to_native_endian();
		
		let value = (native & 0x7FFFFFFF) as u64;
		
		let is_minutes = native & 0x80000000 != 0;
		if is_minutes
		{
			value * 60
		}
		else
		{
			value
		}
	}
}
