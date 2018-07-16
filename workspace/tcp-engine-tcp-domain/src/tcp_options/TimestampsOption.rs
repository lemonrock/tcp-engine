// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A TCP timestamps option.
#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(C, packed)]
pub struct TimestampsOption
{
	/// "TSval"
	pub TSval: NetworkEndianU32,
	
	/// "TSecr"
	///
	/// RFC 7323, Section 3.2: "The TSecr field is valid if the ACK bit is set in the TCP header.
	/// If the ACK bit is not set in the outgoing TCP header, the sender of that segment SHOULD set the TSecr field to zero.
	/// ...
	/// When the ACK bit is not set, the receiver MUST ignore the value of the TSecr field."
	pub TSecr: NetworkEndianU32,
}

impl TimestampsOption
{
	#[doc(hidden)]
	pub const Kind: u8 = 8;
	
	#[doc(hidden)]
	pub const KnownLength: usize = 10;
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn from_TSval_only(TSval: NetworkEndianU32) -> Self
	{
		Self
		{
			TSval,
			TSecr: NetworkEndianU32::Zero,
		}
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn from_TSval_and_TSecr(TSval: NetworkEndianU32, TSecr: NetworkEndianU32) -> Self
	{
		Self
		{
			TSval,
			TSecr,
		}
	}
}
